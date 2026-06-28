# detection/detect_handler.py
import json
import logging
import os

import boto3

from engine.notifier.notify import publish as send_alert

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
TOPIC_ARN = os.environ["FINDINGS_TOPIC_ARN"]

# Compliance controls + severity + MITRE are resolved from mapping.yaml at deploy time
# (Terraform yamldecode) and injected here, so the Lambda needs no YAML parsing at runtime.
ENRICHMENT = json.loads(os.environ.get("ENRICHMENT", "{}"))


def handler(event, context):
    detail = event.get("detail", {})
    bucket = detail.get("requestParameters", {}).get("bucketName", "unknown")
    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    action = detail.get("eventName", "unknown")
    finding = {
        "finding_id": "PUBLIC_S3_BUCKET",
        "resource": bucket,
        "actor": actor,
        "action": action,
    }
    # Findings are never raw: attach the compliance mapping before anyone consumes them.
    finding.update(ENRICHMENT)
    logger.info("Finding: %s", json.dumps(finding))

    sns.publish(TopicArn=TOPIC_ARN, Message=json.dumps(finding))

    # A compliance-aware alert to the ops inbox. Best-effort: a notification failure must
    # never stop the finding from reaching remediation.
    try:
        send_alert(finding)
    except Exception as e:  # noqa: BLE001
        logger.warning("Alert publish failed: %s", e)
    return finding
