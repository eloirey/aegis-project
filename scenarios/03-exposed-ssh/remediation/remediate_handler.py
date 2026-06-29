# remediation/remediate_handler.py
import json
import logging

import boto3
from botocore.exceptions import ClientError

from engine.store.findings import record_remediation

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")


# Rebuild the boto3 IpPermission from the rule the detector flagged, so we revoke exactly
# what was opened and leave every other rule on the group untouched. An all-traffic (-1)
# rule carries no ports.
def _ip_permission(rule):
    perm = {"IpProtocol": rule["protocol"]}
    if rule["protocol"] != "-1":
        perm["FromPort"] = rule["from_port"]
        perm["ToPort"] = rule["to_port"]
    if rule.get("v4"):
        perm["IpRanges"] = [{"CidrIp": c} for c in rule["v4"]]
    if rule.get("v6"):
        perm["Ipv6Ranges"] = [{"CidrIpv6": c} for c in rule["v6"]]
    return perm


def _persist(finding):
    # Best-effort: flip the dashboard row to remediated, never fail the remediation itself
    # over a bookkeeping error.
    try:
        record_remediation(finding)
    except Exception as e:  # noqa: BLE001
        logger.warning("Persist remediation failed: %s", e)


def handler(event, context):
    finding = json.loads(event["Records"][0]["Sns"]["Message"])

    if finding.get("finding_id") != "EXPOSED_SSH":
        logger.info("Ignoring unrelated finding %s", finding.get("finding_id"))
        return {"skipped": finding.get("finding_id")}

    group_id = finding["resource"]
    perm = _ip_permission(finding["offending_rule"])

    try:
        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[perm])
    except ClientError as e:
        # Already revoked (e.g. a duplicate event): the desired state is reached anyway.
        if e.response["Error"]["Code"] == "InvalidPermission.NotFound":
            logger.info("Rule already absent on %s", group_id)
            _persist(finding)
            return {"already_clear": group_id}
        raise

    logger.info("Revoked exposed SSH rule on %s", group_id)
    _persist(finding)
    return {"remediated": group_id}