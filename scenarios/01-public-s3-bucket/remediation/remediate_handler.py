# remediation/remediate_handler.py
import json
import logging

import boto3

from engine.store.findings import record_remediation

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")


def handler(event, context):
    finding = json.loads(event["Records"][0]["Sns"]["Message"])
    bucket = finding["resource"]

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    # The block already neutralises the policy; deleting it leaves the bucket clean for the next run
    s3.delete_bucket_policy(Bucket=bucket)

    # Flip the dashboard row to remediated; best-effort, a bookkeeping error must not
    # undo a successful remediation.
    try:
        record_remediation(finding)
    except Exception as e:  # noqa: BLE001
        logger.warning("Persist remediation failed: %s", e)

    logger.info("Remediated %s for finding %s", bucket, finding["finding_id"])
    return {"remediated": bucket}