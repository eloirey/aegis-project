# remediation/remediate_handler.py
import json
import logging

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")

QUARANTINE_POLICY_NAME = "aegis-quarantine"

# An explicit Deny always wins over any Allow, so this neutralises the escalation
# without detaching anything: the AdministratorAccess grant stays in place
# (reversible for false positives) while every escalation, persistence and
# self-rescue path is blocked. The principal keeps day-to-day access; only the
# kill chain is cut. Deleting this inline policy fully reverts the action.
QUARANTINE_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AegisQuarantineDeny",
            "Effect": "Deny",
            "Action": [
                "iam:AttachUserPolicy",
                "iam:AttachRolePolicy",
                "iam:AttachGroupPolicy",
                "iam:PutUserPolicy",
                "iam:PutRolePolicy",
                "iam:PutGroupPolicy",
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion",
                "iam:CreateAccessKey",
                "iam:CreateLoginProfile",
                "iam:UpdateLoginProfile",
                "iam:CreateUser",
                "iam:CreateRole",
                "iam:UpdateAssumeRolePolicy",
                "iam:AddUserToGroup",
                "iam:PassRole",
                # Denying the detach/delete verbs makes the quarantine tamper-proof
                # against the compromised identity itself; the operator (a different
                # principal) can still remove it to revert.
                "iam:DetachUserPolicy",
                "iam:DetachRolePolicy",
                "iam:DeleteUserPolicy",
                "iam:DeleteRolePolicy",
            ],
            "Resource": "*",
        }
    ],
}


def handler(event, context):
    finding = json.loads(event["Records"][0]["Sns"]["Message"])

    # The topic can fan out several finding types; only act on our own.
    if finding.get("finding_id") != "PRIVILEGED_IAM":
        logger.info("Ignoring unrelated finding %s", finding.get("finding_id"))
        return {"skipped": finding.get("finding_id")}

    principal_type = finding.get("principal_type")
    name = finding["resource"]
    document = json.dumps(QUARANTINE_DOCUMENT)

    if principal_type == "user":
        iam.put_user_policy(
            UserName=name, PolicyName=QUARANTINE_POLICY_NAME, PolicyDocument=document
        )
    elif principal_type == "role":
        iam.put_role_policy(
            RoleName=name, PolicyName=QUARANTINE_POLICY_NAME, PolicyDocument=document
        )
    else:
        logger.warning("Unknown principal_type for %s; no action taken", name)
        return {"skipped": name}

    logger.info("Quarantined %s %s for finding %s", principal_type, name, finding["finding_id"])
    return {"quarantined": name, "principal_type": principal_type}
