"""Certbot Route53 authenticator plugin with CNAME following (patched)."""
import collections
import logging
import time
from typing import Any, Callable, DefaultDict, Dict, Iterable, List, Type

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from acme import challenges
from certbot import achallenges, errors, interfaces
from certbot.achallenges import AnnotatedChallenge
from certbot.plugins import common

logger = logging.getLogger(__name__)

INSTRUCTIONS = (
    "To use certbot-dns-route53, configure credentials as described at "
    "https://boto3.readthedocs.io/en/latest/guide/configuration.html#best-practices-for-configuring-credentials "
    "and add the necessary permissions for Route53 access."
)

class Authenticator(common.Plugin, interfaces.Authenticator):
    """Route53 Authenticator with CNAME following."""

    description = ("Obtain certificates using a DNS TXT record (if you are using AWS Route53 for DNS).")
    ttl = 10

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.r53 = boto3.client("route53")
        self._attempt_cleanup = False
        self._resource_records: DefaultDict[str, List[Dict[str, str]]] = collections.defaultdict(list)

    def more_info(self) -> str:
        return "Solve a DNS01 challenge using AWS Route53"

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        pass

    def auth_hint(self, failed_achalls: List[achallenges.AnnotatedChallenge]) -> str:
        return (
            'The Certificate Authority failed to verify the DNS TXT records created by '
            '--dns-route53. Ensure the above domains have their DNS hosted by AWS Route53.'
        )

    def prepare(self) -> None:
        pass

    def get_chall_pref(self, unused_domain: str) -> Iterable[Type[challenges.Challenge]]:
        return [challenges.DNS01]

    def perform(self, achalls: List[AnnotatedChallenge]) -> List[challenges.ChallengeResponse]:
        self._attempt_cleanup = True

        try:
            change_ids = [
                self._change_txt_record("UPSERT",
                  achall.validation_domain_name(achall.domain),
                  achall.validation(achall.account_key))
                for achall in achalls
            ]

            for change_id in change_ids:
                self._wait_for_change(change_id)
        except (NoCredentialsError, ClientError) as e:
            logger.debug('Encountered error during perform: %s', e, exc_info=True)
            raise errors.PluginError("\n".join([str(e), INSTRUCTIONS]))
        return [achall.response(achall.account_key) for achall in achalls]

    def cleanup(self, achalls: List[achallenges.AnnotatedChallenge]) -> None:
        if self._attempt_cleanup:
            for achall in achalls:
                domain = achall.domain
                validation_domain_name = achall.validation_domain_name(domain)
                validation = achall.validation(achall.account_key)
                self._cleanup(validation_domain_name, validation)

    def _cleanup(self, validation_name: str, validation: str) -> None:
        try:
            self._change_txt_record("DELETE", validation_name, validation)
        except (NoCredentialsError, ClientError) as e:
            logger.debug('Encountered error during cleanup: %s', e, exc_info=True)

    def _find_zone_id_for_domain(self, domain: str) -> str:
        paginator = self.r53.get_paginator("list_hosted_zones")
        zones = []
        target_labels = domain.rstrip(".").split(".")
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if zone["Config"]["PrivateZone"]:
                    continue
                candidate_labels = zone["Name"].rstrip(".").split(".")
                if candidate_labels == target_labels[-len(candidate_labels):]:
                    zones.append((zone["Name"], zone["Id"]))

        if not zones:
            raise errors.PluginError(
                f"Unable to find a Route53 hosted zone for {domain}"
            )

        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def _find_zone_id_for_domain_or_alias(self, domain: str) -> (str, str):
        """Follow CNAME if necessary to find the correct hosted zone."""
        zone_id = self._find_zone_id_for_domain(domain)
        paginator = self.r53.get_paginator("list_resource_record_sets")
        target = f"{domain}."
        alias = None

        for page in paginator.paginate(HostedZoneId=zone_id):
            for record in page["ResourceRecordSets"]:
                if record["Name"] == target and record["Type"] == "CNAME":
                    alias = record["ResourceRecords"][0]["Value"].rstrip(".")
                    break

        if alias:
            return self._find_zone_id_for_domain(alias), alias
        return zone_id, domain

    def _change_txt_record(self, action: str, validation_domain_name: str, validation: str) -> str:
        zone_id, real_validation_domain_name = self._find_zone_id_for_domain_or_alias(validation_domain_name)

        rrecords = self._resource_records[real_validation_domain_name]
        challenge = {"Value": f'"{validation}"'}
        if action == "DELETE":
            rrecords.remove(challenge)
            if rrecords:
                action = "UPSERT"
            else:
                rrecords = [challenge]
        else:
            rrecords.append(challenge)

        response = self.r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": f"certbot-dns-route53 certificate validation {action}",
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": real_validation_domain_name,
                            "Type": "TXT",
                            "TTL": self.ttl,
                            "ResourceRecords": rrecords,
                        }
                    }
                ]
            }
        )
        return response["ChangeInfo"]["Id"]

    def _wait_for_change(self, change_id: str) -> None:
        for _ in range(0, 120):
            response = self.r53.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            time.sleep(5)
        raise errors.PluginError(
            "Timed out waiting for Route53 change. Current status: %s" %
            response["ChangeInfo"]["Status"]
        )


class HiddenAuthenticator(Authenticator):
    """A hidden shim around certbot-dns-route53 for backwards compatibility."""

    hidden = True
