"""
engine.notifier.notify
----------------------
Formats an enriched finding into a human-readable alert and publishes it to SNS.
"""
import os

import boto3

TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")

_SEVERITY_ICON = {"HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}
_TITLES = {
    "PUBLIC_S3_BUCKET": "Public S3 bucket",
    "PRIVILEGED_IAM": "IAM privilege escalation",
    "EXPOSED_SSH": "SSH exposed to the internet",
}

# Lazy client so importing this module (e.g. in tests) doesn't require AWS config.
_sns = None


def _region_from_arn(arn):
    # arn:aws:sns:<region>:<account>:<name> — the alerts topic may live in a different
    # region than the Lambda (the IAM scenario runs in us-east-1, alerts in eu-west-1),
    # so publish through a client bound to the topic's own region.
    parts = arn.split(":")
    return parts[3] if len(parts) > 3 and parts[3] else None


def _client():
    global _sns
    if _sns is None:
        region = _region_from_arn(TOPIC_ARN)
        _sns = boto3.client("sns", region_name=region) if region else boto3.client("sns")
    return _sns


def format_alert(finding: dict) -> str:
    """Render an enriched finding as a readable alert string."""
    severity = finding.get("severity") or "n/a"
    tag = _SEVERITY_ICON.get(finding.get("severity"), "[INFO]")
    title = _TITLES.get(finding.get("finding_id"), finding.get("finding_id", "Finding"))
    controls = finding.get("controls", {})

    violates = []
    if controls.get("ens"):
        violates.append("ENS " + ", ".join(controls["ens"]))
    if controls.get("nis2"):
        violates.append("NIS2 " + ", ".join(controls["nis2"]))
    if controls.get("cis_aws"):
        violates.append("CIS AWS " + ", ".join(controls["cis_aws"]))

    lines = [
        f"{tag} {title} detected - {finding.get('resource', 'unknown')}",
        f"Severity: {severity}",
        f"Actor: {finding.get('actor', 'unknown')}",
        f"Detected action: {finding.get('action', 'n/a')}",
        f"Violates: {' | '.join(violates) if violates else 'n/a'}",
        "Response: automatic remediation dispatched via SNS",
    ]
    if finding.get("mitre_attack"):
        lines.insert(2, "MITRE ATT&CK: " + ", ".join(finding["mitre_attack"]))
    return "\n".join(lines)


def publish(finding: dict) -> None:
    """Publish the formatted alert to the alerts SNS topic."""
    _client().publish(
        TopicArn=TOPIC_ARN,
        Subject="[Aegis Project] Security finding",
        Message=format_alert(finding),
    )