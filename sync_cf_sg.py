#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Version: v1.0.0
Cloudflare Security Group Sync 
Author: Jordi Fuerte Amill
Linkedin: https://www.linkedin.com/in/jfamill/
Github: https://github.com/Jfami
License: BSD 3-Clause
Repository: https://github.com/Jfami/AWS_Cloudflare_SecurityGroups
"""

import json
import urllib3
import boto3

# Adjust the following to match your environment
REGION = "eu-west-3"

# Example Security Groups, replace with real ones
SGS = [
    {"id": "sg-XXXXXXXX", "label": "Prod"},
    {"id": "sg-YYYYYYYY", "label": "Dev"}
]

def lambda_handler(event, context):
    """
    AWS Lambda entry point.
    Fetches Cloudflare IPs and synchronizes ports 80/443 on specified SGs.
    """
    cf_ipv4, cf_ipv6 = get_cloudflare_ips()
    ec2 = boto3.client('ec2', region_name=REGION)

    for sg_info in SGS:
        sg_id = sg_info["id"]
        label = sg_info["label"]
        try:
            sync_security_group(ec2, sg_id, cf_ipv4, cf_ipv6, label)
        except Exception as e:
            print(f"[{label}] Error synchronizing SG {sg_id}: {e}")

    return {
        "statusCode": 200,
        "body": "Sync completed"
    }

def get_cloudflare_ips():
    """
    Calls the official Cloudflare API: https://api.cloudflare.com/client/v4/ips
    Returns two sets: (cf_ipv4, cf_ipv6).
    """
    url = "https://api.cloudflare.com/client/v4/ips"
    http = urllib3.PoolManager()
    resp = http.request("GET", url)
    if resp.status != 200:
        raise Exception(f"Error calling Cloudflare API. Status: {resp.status}")

    data = json.loads(resp.data.decode("utf-8"))
    if not data.get("success", False):
        raise Exception(f"Negative response from Cloudflare: {data.get('errors')}")

    result = data.get("result", {})
    ipv4_cidrs = result.get("ipv4_cidrs", [])
    ipv6_cidrs = result.get("ipv6_cidrs", [])
    print(f"Cloudflare: {len(ipv4_cidrs)} IPv4 ranges, {len(ipv6_cidrs)} IPv6 ranges")

    cf_ipv4 = set(ipv4_cidrs)
    cf_ipv6 = set(ipv6_cidrs)
    return cf_ipv4, cf_ipv6

def sync_security_group(ec2, sg_id, cf_ipv4, cf_ipv6, label=""):
    """
    Synchronizes ports 80 and 443 of a Security Group with Cloudflare IP ranges.
    - Describes the current SG.
    - Gathers existing IPv4/IPv6 on ports 80/443.
    - Finds obsolete IPs to revoke and new IPs to add.
    - Revokes only obsolete IPs, adds only new ones.
    - Leaves other ports unchanged.
    """
    response = ec2.describe_security_groups(GroupIds=[sg_id])
    sg_desc = response["SecurityGroups"][0]
    inbound = sg_desc.get("IpPermissions", [])

    current_ipv4_80 = set()
    current_ipv4_443 = set()
    current_ipv6_80 = set()
    current_ipv6_443 = set()

    for perm in inbound:
        from_p = perm.get("FromPort")
        to_p = perm.get("ToPort")
        proto = perm.get("IpProtocol")

        # Check if it's TCP:80
        if proto == "tcp" and from_p == 80 and to_p == 80:
            for ipr in perm.get("IpRanges", []):
                cidr = ipr.get("CidrIp")
                if cidr:
                    current_ipv4_80.add(cidr)
            for ipr6 in perm.get("Ipv6Ranges", []):
                cidr6 = ipr6.get("CidrIpv6")
                if cidr6:
                    current_ipv6_80.add(cidr6)

        # Check if it's TCP:443
        elif proto == "tcp" and from_p == 443 and to_p == 443:
            for ipr in perm.get("IpRanges", []):
                cidr = ipr.get("CidrIp")
                if cidr:
                    current_ipv4_443.add(cidr)
            for ipr6 in perm.get("Ipv6Ranges", []):
                cidr6 = ipr6.get("CidrIpv6")
                if cidr6:
                    current_ipv6_443.add(cidr6)

    # Compute differences (obsolete vs. new)
    # Port 80
    to_revoke_80_v4 = current_ipv4_80 - cf_ipv4
    to_add_80_v4 = cf_ipv4 - current_ipv4_80

    to_revoke_80_v6 = current_ipv6_80 - cf_ipv6
    to_add_80_v6 = cf_ipv6 - current_ipv6_80

    # Port 443
    to_revoke_443_v4 = current_ipv4_443 - cf_ipv4
    to_add_443_v4 = cf_ipv4 - current_ipv4_443

    to_revoke_443_v6 = current_ipv6_443 - cf_ipv6
    to_add_443_v6 = cf_ipv6 - current_ipv6_443

    # Revoke obsolete IPs
    revoke_80 = build_revoke_permission(80, 80, to_revoke_80_v4, to_revoke_80_v6)
    if revoke_80:
        try:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[revoke_80])
            print(f"[{label}] Revoked {len(to_revoke_80_v4)} IPv4 and {len(to_revoke_80_v6)} IPv6 from port 80.")
        except Exception as e:
            print(f"[{label}] Error revoking IPs on port 80: {e}")

    revoke_443 = build_revoke_permission(443, 443, to_revoke_443_v4, to_revoke_443_v6)
    if revoke_443:
        try:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[revoke_443])
            print(f"[{label}] Revoked {len(to_revoke_443_v4)} IPv4 and {len(to_revoke_443_v6)} IPv6 from port 443.")
        except Exception as e:
            print(f"[{label}] Error revoking IPs on port 443: {e}")

    # Authorize new IPs
    add_80 = build_authorize_permission(80, 80, to_add_80_v4, to_add_80_v6)
    if add_80:
        try:
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[add_80])
            print(f"[{label}] Added {len(to_add_80_v4)} IPv4 and {len(to_add_80_v6)} IPv6 to port 80.")
        except Exception as e:
            print(f"[{label}] Error authorizing IPs on port 80: {e}")

    add_443 = build_authorize_permission(443, 443, to_add_443_v4, to_add_443_v6)
    if add_443:
        try:
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[add_443])
            print(f"[{label}] Added {len(to_add_443_v4)} IPv4 and {len(to_add_443_v6)} IPv6 to port 443.")
        except Exception as e:
            print(f"[{label}] Error authorizing IPs on port 443: {e}")

    print(f"[{label}] Sync completed on SG {sg_id}.")

def build_revoke_permission(from_port, to_port, ipv4_list, ipv6_list):
    """Builds an IpPermission object to revoke specific IPs."""
    if not ipv4_list and not ipv6_list:
        return None
    perm = {
        'IpProtocol': 'tcp',
        'FromPort': from_port,
        'ToPort': to_port
    }
    ip_ranges = [{'CidrIp': cidr} for cidr in ipv4_list] if ipv4_list else []
    ipv6_ranges = [{'CidrIpv6': cidr} for cidr in ipv6_list] if ipv6_list else []

    if ip_ranges:
        perm['IpRanges'] = ip_ranges
    if ipv6_ranges:
        perm['Ipv6Ranges'] = ipv6_ranges

    return perm

def build_authorize_permission(from_port, to_port, ipv4_list, ipv6_list):
    """Builds an IpPermission object to authorize specific new IPs."""
    if not ipv4_list and not ipv6_list:
        return None
    perm = {
        'IpProtocol': 'tcp',
        'FromPort': from_port,
        'ToPort': to_port
    }
    ip_ranges = [{'CidrIp': cidr} for cidr in ipv4_list] if ipv4_list else []
    ipv6_ranges = [{'CidrIpv6': cidr} for cidr in ipv6_list] if ipv6_list else []

    if ip_ranges:
        perm['IpRanges'] = ip_ranges
    if ipv6_ranges:
        perm['Ipv6Ranges'] = ipv6_ranges

    return perm