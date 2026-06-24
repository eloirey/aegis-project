import argparse
import sys

import boto3
from botocore import UNSIGNED
from botocore.config import Config


# UNSIGNED forces requests without any credentials, mimicking an external
# attacker. With signed requests we'd authenticate as the owner and prove nothing.
def anonymous_client():
    return boto3.client("s3", config=Config(signature_version=UNSIGNED))


def run(bucket: str, key: str) -> int:
    s3 = anonymous_client()
    print(f"[*] Target bucket: {bucket}")
    print(f"[*] Attempting anonymous read of '{key}' (no credentials)...\n")

    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        body = response["Body"].read().decode("utf-8", errors="replace")
        print("[!] SUCCESS - object read without any credentials:\n")
        print(body)
        print("[!] The bucket is publicly exposed. This is the data leak.")
        return 0
    except s3.exceptions.NoSuchKey:
        print(f"[-] Object '{key}' not found in the bucket.")
        return 1
    except Exception as e:
        # AccessDenied here is the GOOD outcome: after remediation the bucket
        # is locked down and the attack stops working.
        print(f"[+] Access denied or error - bucket is not publicly readable.")
        print(f"    ({type(e).__name__}: {e})")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Anonymous S3 read demo (lab only).")
    parser.add_argument("--bucket", required=True, help="Target lab bucket name")
    parser.add_argument("--key", default="credentials.txt", help="Object key to read")
    args = parser.parse_args()
    sys.exit(run(args.bucket, args.key))


if __name__ == "__main__":
    main()