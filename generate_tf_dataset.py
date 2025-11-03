#!/usr/bin/env python3
"""
generate_tf_dataset.py
-----------------------
Creates a synthetic Terraform corpus for IaC auditor testing.

Each .tf file represents a resource with either secure or insecure configuration.
You’ll get examples of:
  - Public S3 buckets
  - Open security groups
  - Wildcard IAM policies
"""

import os, random

OUT_DIR = "tf_dataset"
NUM_FILES = 50  # total number of Terraform files to generate
os.makedirs(OUT_DIR, exist_ok=True)

# --------------------
# Resource templates
# --------------------
s3_templates = [
    ('good', 'acl = "private"'),
    ('bad_public', 'acl = "public-read"'),
    ('bad_public_rw', 'acl = "public-read-write"')
]

sg_templates = [
    ('good', 'ingress { from_port = 22 to_port = 22 cidr_blocks = ["10.0.0.0/24"] }'),
    ('bad_open', 'ingress { from_port = 0 to_port = 65535 cidr_blocks = ["0.0.0.0/0"] }')
]

iam_templates = [
    ('good', 'policy = jsonencode({ Statement = [{ Action = ["s3:GetObject"], Effect = "Allow", Resource = ["arn:aws:s3:::mybucket/*"] }] })'),
    ('bad_wild', 'policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })')
]

templates = {
    "aws_s3_bucket": s3_templates,
    "aws_security_group": sg_templates,
    "aws_iam_policy": iam_templates
}

# --------------------
# File generation
# --------------------
for i in range(NUM_FILES):
    rtype = random.choice(list(templates.keys()))
    label, config = random.choice(templates[rtype])
    resource_name = f"{label}_{rtype.split('_')[-1]}_{i}"

    filename = os.path.join(OUT_DIR, f"{resource_name}.tf")
    with open(filename, "w") as f:
        f.write(f'resource "{rtype}" "{resource_name}" {{\n')
        f.write(f'  name = "{resource_name}"\n')
        f.write(f'  {config}\n')
        f.write("}\n")

print(f"[+] Generated {NUM_FILES} Terraform test files in '{OUT_DIR}/'")
