# detection/detect_handler.py
import json
import logging
import os
from urllib.parse import unquote

import boto3

from engine.notifier.notify import publish as send_alert
from engine.store.findings import record_detection

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
TOPIC_ARN = os.environ["FINDINGS_TOPIC_ARN"]

# Compliance controls + severity + MITRE are resolved from mapping.yaml at deploy time
# (Terraform yamldecode) and injected here, so the Lambda needs no YAML parsing at runtime.
ENRICHMENT = json.loads(os.environ.get("ENRICHMENT", "{}"))

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


# Attach events name a managed policy on a user or a role; the principal key
# tells us which, and the name is what remediation needs to act on.
def _principal(params):
    if "userName" in params:
        return "user", params["userName"]
    if "roleName" in params:
        return "role", params["roleName"]
    return "unknown", "unknown"


# An inline document is admin-equivalent when any Allow statement grants Action
# "*" over Resource "*". CloudTrail delivers policyDocument URL-encoded, so try
# the decoded form first and fall back to the raw string.
def _inline_is_admin(document: str) -> bool:
    if not document:
        return False
    doc = None
    for candidate in (unquote(document), document):
        try:
            doc = json.loads(candidate)
            break
        except (TypeError, json.JSONDecodeError):
            continue
    if doc is None:
        return False

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions and "*" in resources:
            return True
    return False


def _is_dangerous(action: str, params: dict) -> bool:
    if action in ("AttachUserPolicy", "AttachRolePolicy"):
        return params.get("policyArn") == ADMIN_POLICY_ARN
    if action in ("PutUserPolicy", "PutRolePolicy"):
        return _inline_is_admin(params.get("policyDocument", ""))
    return False


def handler(event, context):
    detail = event.get("detail", {})
    action = detail.get("eventName", "unknown")
    params = detail.get("requestParameters", {}) or {}
    actor = detail.get("userIdentity", {}).get("arn", "unknown")

    # Detect on policy content, not on who did it: a benign grant (e.g. attaching
    # ReadOnlyAccess) is not a finding even from an unexpected actor.
    if not _is_dangerous(action, params):
        logger.info("Ignored non-privileged %s by %s", action, actor)
        return {"finding_id": None, "action": action}

    principal_type, principal_name = _principal(params)
    finding = {
        "id": detail.get("eventID"),
        "finding_id": "PRIVILEGED_IAM",
        "resource": principal_name,
        "actor": actor,
        "action": action,
        "principal_type": principal_type,
    }
    # Findings are never raw: attach the compliance mapping before anyone consumes them.
    finding.update(ENRICHMENT)
    logger.info("Finding: %s", json.dumps(finding))

    # Persist the detection so the live dashboard can track this finding; best-effort,
    # a storage failure must not stop it from reaching remediation.
    try:
        record_detection(finding)
    except Exception as e:  # noqa: BLE001
        logger.warning("Persist detection failed: %s", e)

    sns.publish(TopicArn=TOPIC_ARN, Message=json.dumps(finding))

    # A compliance-aware alert to the ops inbox. Best-effort: a notification failure must
    # never stop the finding from reaching remediation.
    try:
        send_alert(finding)
    except Exception as e:  # noqa: BLE001
        logger.warning("Alert publish failed: %s", e)
    return finding