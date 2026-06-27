# detection/detect_handler.py
import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
TOPIC_ARN = os.environ["FINDINGS_TOPIC_ARN"]

SSH_PORT = 22
WORLD_V4 = "0.0.0.0/0"
WORLD_V6 = "::/0"


# CloudTrail nests permissions/ranges under an "items" list, unlike the boto3 API shape.
def _items(d, key):
    v = d.get(key) or {}
    return v.get("items", []) if isinstance(v, dict) else []


# A permission reaches SSH when it is all-traffic (-1) or a tcp range covering port 22.
def _covers_ssh(perm):
    proto = str(perm.get("ipProtocol"))
    if proto == "-1":
        return True
    if proto not in ("tcp", "6"):
        return False
    fr, to = perm.get("fromPort"), perm.get("toPort")
    return fr is not None and to is not None and fr <= SSH_PORT <= to


def _world_cidrs(perm):
    v4 = [r.get("cidrIp") for r in _items(perm, "ipRanges") if r.get("cidrIp") == WORLD_V4]
    v6 = [r.get("cidrIpv6") for r in _items(perm, "ipv6Ranges") if r.get("cidrIpv6") == WORLD_V6]
    return v4, v6


def handler(event, context):
    detail = event.get("detail", {})
    action = detail.get("eventName", "unknown")
    params = detail.get("requestParameters", {}) or {}
    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    group_id = params.get("groupId", "unknown")

    # Detect on content: the finding fires only when a rule actually opens SSH to the
    # whole internet, regardless of who added it. Anything narrower is ignored.
    for perm in _items(params, "ipPermissions"):
        if not _covers_ssh(perm):
            continue
        v4, v6 = _world_cidrs(perm)
        if not (v4 or v6):
            continue
        finding = {
            "finding_id": "EXPOSED_SSH",
            "resource": group_id,
            "actor": actor,
            "action": action,
            # The exact rule that triggered, so remediation revokes only this and nothing else.
            "offending_rule": {
                "protocol": str(perm.get("ipProtocol")),
                "from_port": perm.get("fromPort"),
                "to_port": perm.get("toPort"),
                "v4": v4,
                "v6": v6,
            },
        }
        logger.info("Finding: %s", json.dumps(finding))
        sns.publish(TopicArn=TOPIC_ARN, Message=json.dumps(finding))
        return finding

    logger.info("Ignored non-exposing %s on %s by %s", action, group_id, actor)
    return {"finding_id": None, "action": action}
