"""
engine.notifier.notify
----------------------
Formats an enriched finding into a human-readable alert and publishes it to SNS.

SKELETON — implement the TODOs.
"""

import os

import boto3

sns = boto3.client("sns")

TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")


def format_alert(finding: dict) -> str:
    """Render a finding as a readable alert string."""
    # TODO: produce something like:
    #
    #   🔴 Public S3 bucket detected — aegis-project-lab-public-ab12
    #   Actor: arn:aws:iam::123456789012:user/intern
    #   Violates: ENS [mp.info], NIS2 Art. 21, CIS AWS 2.1.x
    #   Action: auto-remediated (Block Public Access re-enabled)
    #
    # Pull the fields from the enriched finding dict.
    raise NotImplementedError("TODO: format the alert text")


def publish(finding: dict) -> None:
    """Publish the formatted alert to the SNS topic."""
    # TODO: message = format_alert(finding)
    #       sns.publish(TopicArn=TOPIC_ARN, Subject="[Aegis Project] Finding", Message=message)
    raise NotImplementedError("TODO: publish to SNS")
