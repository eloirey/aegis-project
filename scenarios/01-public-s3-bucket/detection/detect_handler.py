import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


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
    return finding