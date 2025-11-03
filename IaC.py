#!/usr/bin/env python3
"""
IaC Misconfiguration Auditor
-----------------------------
Scans Terraform (.tf) files for insecure patterns such as:
 - Public S3 buckets (public-read / public-read-write)
 - Security groups open to the world (0.0.0.0/0)
 - IAM policies with wildcard permissions ("*")

Outputs results to: iac_findings.csv
"""

import hcl2 # type: ignore
import os
import csv
import datetime as dt
import sys

OUTPUT_CSV = "iac_findings.csv"

def check_resource(filepath, rtype, name, block):
    findings = []

    # S3 bucket misconfiguration
    if rtype == "aws_s3_bucket":
        acl = block.get("acl", [""])[0] if isinstance(block.get("acl"), list) else block.get("acl", "")
        if acl in ("public-read", "public-read-write"):
            findings.append((name, f"S3 bucket with public ACL ({acl})"))

    # Security group misconfiguration
    if rtype == "aws_security_group":
        ingress = block.get("ingress", [])
        for rule in ingress:
            cidr_blocks = rule.get("cidr_blocks", [])
            for cidr in cidr_blocks:
                if cidr == "0.0.0.0/0":
                    findings.append((name, "Security group allows 0.0.0.0/0 (open to world)"))

    # IAM policy misconfiguration
    if rtype == "aws_iam_policy":
        policy_doc = block.get("policy")
        if policy_doc:
            policy_text = str(policy_doc)
            if '"Action": "*"' in policy_text or '"Resource": "*"' in policy_text:
                findings.append((name, "IAM policy allows wildcard permissions (*)"))
            if '"Action": ["*"]' in policy_text:
                findings.append((name, "IAM policy allows full admin (*:* on all resources)"))

    return findings


def scan_tf_file(filepath):
    findings = []
    try:
        with open(filepath, "r") as f:
            data = hcl2.load(f)
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
        return []

    resources = data.get("resource", {})
    if isinstance(resources, list):
        # Handle list-based structure
        for res in resources:
            for rtype, blocks in res.items():
                for name, block in blocks.items():
                    findings.extend(check_resource(filepath, rtype, name, block))
    elif isinstance(resources, dict):
        # Handle dict-based structure
        for rtype, blocks in resources.items():
            for name, block in blocks.items():
                findings.extend(check_resource(filepath, rtype, name, block))

    return findings


def scan_directory(path="."):
    all_findings = []
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(".tf"):
                filepath = os.path.join(root, f)
                file_findings = scan_tf_file(filepath)
                for finding in file_findings:
                    # Ensure each finding is a tuple (resource_name, finding_text)
                    if isinstance(finding, (list, tuple)) and len(finding) == 2:
                        all_findings.append((filepath, finding[0], finding[1]))
                    else:
                        all_findings.append((filepath, "unknown", str(finding)))

    # Write to CSV
    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["timestamp", "file", "resource_name", "finding"])
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        for file, res_name, finding_text in all_findings:
            writer.writerow([timestamp, file, res_name, finding_text])

    # Print summary safely
    if all_findings:
        print(f"[*] Scan complete. {len(all_findings)} findings written to {OUTPUT_CSV}")
        for file, res_name, finding_text in all_findings:
            print(f"{file} - {res_name} -> {finding_text}")
    else:
        print("[*] Scan complete. No findings detected.")



if __name__ == "__main__":
    # Allow scanning of a specific file if passed as argument
    if len(sys.argv) == 2:
        target = sys.argv[1]
        findings = scan_tf_file(target)
        if findings:
            print(f"[*] Scan complete. {len(findings)} findings found in {target}")
            for f in findings:
                print(f"{target} - {f[0]} -> {f[1]}")
        else:
            print(f"[*] Scan complete. No findings in {target}")
    else:
        scan_directory(".")
