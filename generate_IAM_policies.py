#!/usr/bin/env python3
"""
generate_iam_policies.py
------------------------
Creates mock IAM policy JSON files to test IAM monitoring.

Generates both safe (least-privilege) and risky (wildcard / escalation) policies.
"""

import os, json, random

OUT_DIR = "iam_policies"
os.makedirs(OUT_DIR, exist_ok=True)

good_policies = [
    {
        "PolicyName": "ReadOnlyS3Policy",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::secure-bucket/*"]
            }]
        }
    }
]

bad_policies = [
    {
        "PolicyName": "FullAdminPolicy",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }
    },
    {
        "PolicyName": "PrivilegeEscalationPolicy",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:PassRole", "iam:AttachUserPolicy"],
                "Resource": "*"
            }]
        }
    }
]

all_policies = good_policies + bad_policies

for policy in all_policies:
    name = policy["PolicyName"]
    with open(os.path.join(OUT_DIR, f"{name}.json"), "w") as f:
        json.dump(policy["Document"], f, indent=2)

print(f"[+] Created {len(all_policies)} mock IAM policies in '{OUT_DIR}/'")
