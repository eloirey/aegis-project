"""
Scenario 01 — Attack: anonymous read of a public S3 bucket.

This simulates what an external attacker (or an internet scanner bot) does when it finds
a misconfigured public bucket: it reads the objects WITHOUT any AWS credentials.

⚠️  Lab use only. Point this at YOUR OWN deliberately-public lab bucket.

This is a SKELETON. Implement the TODOs to learn how anonymous (unsigned) S3 access works.
"""

import argparse
import sys

import boto3
from botocore import UNSIGNED
from botocore.config import Config


def anonymous_client():
    """Return an S3 client that sends UNSIGNED requests (i.e. no credentials)."""
    # The UNSIGNED config is the key idea: it proves the bucket is readable by anyone,
    # not just by you with your credentials.
    return boto3.client("s3", config=Config(signature_version=UNSIGNED))


def run(bucket: str, region: str) -> int:
    s3 = anonymous_client()

    print(f"[*] Attempting ANONYMOUS access to bucket: {bucket}")

    # TODO 1: List objects anonymously (s3.list_objects_v2). If this succeeds with no
    #         credentials, the bucket is publicly listable.
    #
    # TODO 2: Download / read one object anonymously (s3.get_object) and print a snippet
    #         to prove exfiltration is possible.
    #
    # TODO 3: Handle the "good" failure case gracefully: if access is DENIED, that means
    #         the bucket is NOT public (e.g. after remediation) — print a clear message.
    #         This lets you re-run the attack AFTER remediation to prove it's now blocked.

    print("[!] TODO: implement the anonymous list + get to complete the attack demo.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Anonymous S3 read demo (lab only).")
    parser.add_argument("--bucket", required=True, help="Target lab bucket name")
    parser.add_argument("--region", default="eu-west-1")
    args = parser.parse_args()
    sys.exit(run(args.bucket, args.region))


if __name__ == "__main__":
    main()
