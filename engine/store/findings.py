"""
engine.store.findings
----------------------
Persists a finding's lifecycle to DynamoDB so the live dashboard has something to follow:
detection writes the row, remediation flips it to remediated. Until now findings only ever
existed in-flight on SNS, with nothing left behind to watch.
"""
import os
import time

import boto3

TABLE_NAME = os.environ.get("FINDINGS_TABLE", "")

# The table lives in the core (eu-west-1). The IAM scenario runs in us-east-1 and writes
# to it cross-region, so bind the client to the table's region the way the notifier does.
TABLE_REGION = os.environ.get("FINDINGS_TABLE_REGION") or None

# Rows clean themselves up via TTL; a week comfortably outlives any demo run.
_TTL_SECONDS = 7 * 24 * 60 * 60

# Lazy so importing this module (e.g. in tests) doesn't require AWS config.
_table = None


def _get_table():
    global _table
    if _table is None:
        kwargs = {"region_name": TABLE_REGION} if TABLE_REGION else {}
        _table = boto3.resource("dynamodb", **kwargs).Table(TABLE_NAME)
    return _table


def record_detection(finding: dict) -> None:
    """Write a freshly detected finding, keyed by its CloudTrail eventID."""
    now = int(time.time())
    item = {
        "id": finding["id"],
        "finding_id": finding.get("finding_id"),
        "resource": finding.get("resource"),
        "actor": finding.get("actor"),
        "action": finding.get("action"),
        "severity": finding.get("severity"),
        "controls": finding.get("controls", {}),
        "status": "detected",
        "detected_at": now,
        "expires_at": now + _TTL_SECONDS,
    }
    if finding.get("mitre_attack"):
        item["mitre_attack"] = finding["mitre_attack"]
    _get_table().put_item(Item=item)


def record_remediation(finding: dict) -> None:
    """Flip the existing row to remediated, leaving the detection data intact."""
    # status is a DynamoDB reserved word, hence the alias.
    _get_table().update_item(
        Key={"id": finding["id"]},
        UpdateExpression="SET #s = :s, remediated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "remediated", ":t": int(time.time())},
    )