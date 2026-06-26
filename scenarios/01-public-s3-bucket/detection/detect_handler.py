# detection/detect_handler.py
import json
import logging
import os
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
TOPIC_ARN = os.environ["FINDINGS_TOPIC_ARN"]


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
    logger.info("Finding: %s", json.dumps(finding))
    # SNS decouples detection from response so a finding can fan out to several responders
    sns.publish(TopicArn=TOPIC_ARN, Message=json.dumps(finding))
    return finding