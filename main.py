#!/usr/bin/env python3
"""
Zero Trust Multi-Cloud Security Framework (Unified)
---------------------------------------------------
Combines:
 - IaC auditing
 - IAM monitoring
 - PDP/PEP enforcement (with multiple simulated users)
 - Auto-remediation
 - Centralized monitoring
"""

import subprocess
import time
import datetime as dt
import json
import os


def run_module(cmd, desc):
    print(f"\n[+] Running {desc} ...")
    result = subprocess.run(cmd, text=True, capture_output=True)
    print(result.stdout)
    if result.stderr:
        print(f"[!] STDERR: {result.stderr}")
    print(f"[+] Completed: {desc}\n{'-'*60}")
    return result


def simulate_requests():
    """
    Runs multiple simulated access requests through PEP → PDP → ARM chain.
    These simulate different contexts, actions, and outcomes.
    """
    requests = [
        ("alice", "s3:GetObject", "arn:aws:s3:::secure-bucket", "192.168.1.12", "device-laptop-001"),   # should ALLOW
        ("bob", "s3:DeleteObject", "arn:aws:s3:::secure-bucket/private", "172.16.5.10", "device-laptop-002"),  # DENY
        ("charlie", "ec2:StartInstances", "arn:aws:ec2:::instance/i-1234567890", "10.0.0.22", "device-admin-001"), # ALLOW
        ("david", "iam:AttachRolePolicy", "arn:aws:iam:::role/AdminRole", "192.168.1.10", "unknown-device-999"), # REVIEW
        ("eve", "s3:ListBucket", "arn:aws:s3:::public-bucket", "8.8.8.8", "device-laptop-001"),  # DENY
        ("frank", "s3:GetObject", "arn:aws:s3:::semi-trusted-bucket", "192.168.1.50", "unknown-device-123"),
        ("ivan", "ec2:DescribeInstances", "arn:aws:ec2:::instance/i-9999999999", "10.0.0.8", "device-admin-002"),
    ]

    for user, action, resource, ip, device in requests:
        print(f"\n[+] Running Access Enforcement Chain for {user} ...")
        cmd = ["python", "PEP.py", user, action, resource, ip, device]
        run_module(cmd, f"Access Enforcement for {user}")
        time.sleep(1)  # simulate time between requests


def aggregate_metrics_from_log(log_file="ztmc_framework_log.json"):
    """Compute metrics dynamically by parsing the centralized event log."""
    if not os.path.exists(log_file):
        return {}

    with open(log_file, "r") as f:
        lines = [json.loads(line) for line in f if line.strip()]

    metrics = {
        "total_access_requests": 0,
        "deny_count": 0,
        "review_count": 0,
        "allow_count": 0,
        "total_remediations": 0,
        "per_cloud": {"AWS": 0, "Azure": 0, "GCP": 0},
        "events_by_type": {}
    }

    for e in lines:
        etype = e.get("event_type", "")
        decision = e.get("decision", "")
        cloud = e.get("cloud", "")

        if etype == "ACCESS_REQUEST":
            metrics["total_access_requests"] += 1
        if etype == "REMEDIATION":
            metrics["total_remediations"] += 1

        if decision == "DENY":
            metrics["deny_count"] += 1
        elif decision == "REVIEW":
            metrics["review_count"] += 1
        elif decision == "ALLOW":
            metrics["allow_count"] += 1

        if cloud in metrics["per_cloud"]:
            metrics["per_cloud"][cloud] += 1

        metrics["events_by_type"][etype] = metrics["events_by_type"].get(etype, 0) + 1

    return metrics


def main():
    print("=" * 70)
    print("🛡️  Zero Trust Multi-Cloud Security Framework (Unified) 🛡️")
    print("=" * 70)

    # 1️⃣ Pre-deployment scan (IaC)
    run_module(["python", "IaC.py"], "IaC Auditing (Terraform scan)")

    # 2️⃣ Post-deployment IAM monitoring
    run_module(["python", "IAM.py"], "IAM Configuration Monitoring")

    # 3️⃣ Simulate multi-user access enforcement
    print("[+] Testing PEP → PDP → ARM pipeline...")
    simulate_requests()

    # 4️⃣ Compute aggregated metrics directly from log
    metrics = aggregate_metrics_from_log()

    # 5️⃣ Display aggregated metrics
    print("\n📊 Framework Metrics Summary:")
    if metrics:
        for k, v in metrics.items():
            print(f" - {k}: {v}")
    else:
        print("⚠️ No metrics available (check monitoring logs)")

    print("\n✅ Framework run complete at", dt.datetime.now().isoformat())


if __name__ == "__main__":
    main()
