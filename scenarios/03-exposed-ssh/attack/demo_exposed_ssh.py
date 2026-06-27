import argparse
import socket
import sys
import time

import boto3
from botocore.exceptions import ClientError


# A security group drops blocked traffic silently rather than refusing it, so a closed
# port times out. Treat timeout/refused/unreachable all as "not reachable".
def port_open(ip: str, port: int, timeout: float = 5.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(64).decode(errors="replace").strip()
            except OSError:
                banner = ""
            return True, banner
    except OSError:
        return False, ""


def run(security_group_id: str, public_ip: str, port: int, cidr: str) -> int:
    ec2 = boto3.client("ec2")

    print(f"[*] Target host:    {public_ip}:{port}")
    print(f"[*] Security group: {security_group_id}")
    print(f"[*] Opening to:     {cidr}\n")

    reachable, _ = port_open(public_ip, port)
    if reachable:
        print(f"[-] Port {port} is already reachable before the attack - nothing to prove.")
        print("    Wait for remediation to close it, or re-deploy the scenario.")
        return 1
    print(f"[*] Pre-check: port {port} not reachable from the internet (security group closed).")

    print(f"[*] Opening port {port} to {cidr} (AuthorizeSecurityGroupIngress)...")
    try:
        ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": cidr, "Description": "aegis-lab exposed ssh"}],
            }],
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code != "InvalidPermission.Duplicate":
            print(f"[-] Could not open the port: {code}")
            return 1
        print("[*] Rule already present; continuing to the reachability check.")

    # Security-group changes propagate in a few seconds; sshd may also still be warming up.
    print("[*] Verifying internet reachability (allowing for propagation)...")
    for _ in range(10):
        reachable, banner = port_open(public_ip, port)
        if reachable:
            print(f"\n[!] SUCCESS - port {port} is now open to {cidr}.")
            if banner:
                print(f"[!] Service responded: {banner}")
            print("[!] The host is exposed to the entire internet.")
            return 0
        time.sleep(3)

    print(f"[-] Rule added but port {port} not reachable yet (sshd may still be starting).")
    return 1


def main():
    parser = argparse.ArgumentParser(
        description="Exposed-SSH demo (lab only): open port 22 to the internet and prove reachability."
    )
    parser.add_argument("--security-group-id", required=True, help="SG to open (terraform output)")
    parser.add_argument("--public-ip", required=True, help="Instance public IP (terraform output)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--cidr", default="0.0.0.0/0")
    args = parser.parse_args()
    sys.exit(run(args.security_group_id, args.public_ip, args.port, args.cidr))


if __name__ == "__main__":
    main()