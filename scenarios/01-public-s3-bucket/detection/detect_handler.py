"""
Scenario 01 — Detection Lambda.

Triggered by EventBridge when a bucket is made (or might be) public. Its job:
  1. Parse the CloudTrail event to extract the bucket name + who did it.
  2. Build a normalized "finding".
  3. Enrich it with the compliance mapping (engine.mapping).
  4. Hand off to remediation (invoke the remediation Lambda or emit an event).
  5. Notify (engine.notifier -> SNS).

SKELETON — implement the TODOs.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    # TODO 1: Extract the bucket name and principal from event["detail"]
    #         (requestParameters.bucketName, userIdentity.arn, eventName, etc.).

    # TODO 2: Build a finding dict, e.g.:
    #   finding = {
    #       "finding_id": "PUBLIC_S3_BUCKET",
    #       "resource": bucket_name,
    #       "actor": principal_arn,
    #       "event_name": event_name,
    #   }

    # TODO 3: Enrich with controls:
    #   from engine.mapping.mapper import enrich
    #   finding = enrich(finding, scenario="01-public-s3-bucket")

    # TODO 4: Trigger remediation (invoke remediation Lambda or put a custom event).

    # TODO 5: Notify:
    #   from engine.notifier.notify import publish
    #   publish(finding)

    logger.info("TODO: implement detection logic")
    return {"status": "detected", "todo": True}
