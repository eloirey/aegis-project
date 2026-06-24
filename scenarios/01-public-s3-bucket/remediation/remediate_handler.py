"""
Scenario 01 — Remediation Lambda.

Given a finding about a public bucket, lock it back down and report what was done.

SKELETON — implement the TODOs.
"""

import logging

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")


def handler(event, context):
    # The 'event' here is the finding produced by the detection Lambda.
    bucket = event.get("resource")
    logger.info("Remediating bucket: %s", bucket)

    if not bucket:
        logger.error("No bucket in finding; nothing to remediate.")
        return {"status": "error", "reason": "missing resource"}

    # TODO 1: Re-enable Block Public Access:
    #   s3.put_public_access_block(
    #       Bucket=bucket,
    #       PublicAccessBlockConfiguration={
    #           "BlockPublicAcls": True,
    #           "IgnorePublicAcls": True,
    #           "BlockPublicPolicy": True,
    #           "RestrictPublicBuckets": True,
    #       },
    #   )

    # TODO 2: Remove the offending public bucket policy if present
    #         (s3.delete_bucket_policy) and/or reset the ACL to private.

    # TODO 3: Return a structured result with a timestamp so the dashboard can compute
    #         time-to-remediate. Consider emitting a "REMEDIATED" event too.

    logger.info("TODO: implement remediation actions")
    return {"status": "remediated", "resource": bucket, "todo": True}
