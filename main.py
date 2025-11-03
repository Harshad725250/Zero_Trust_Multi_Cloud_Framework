#!/usr/bin/env python3
"""
Zero Trust Multi-Cloud Security Framework (Unified)
---------------------------------------------------
Combines:
 - IaC auditing
 - IAM monitoring
 - PDP/PEP enforcement
 - Auto-remediation
 - Centralized monitoring
"""

import subprocess
import time
import datetime as dt
from monitoring import get_metrics_snapshot

def run_module(cmd, desc):
    print(f"\n[+] Running {desc} ...")
    result = subprocess.run(cmd, text=True)
    print(f"[+] Completed: {desc}\n{'-'*60}")
    return result

def main():
    print("="*70)
    print("🛡️  Zero Trust Multi-Cloud Security Framework (Unified) 🛡️")
    print("="*70)

    # 1️⃣  Pre-deployment scan
    run_module(["python", "IaC.py"], "IaC Auditing (Terraform scan)")

    # 2️⃣  Post-deployment IAM monitoring
    run_module(["python", "IAM.py"], "IAM Configuration Monitoring")

    # 3️⃣  Simulate access enforcement
    print("[+] Testing PEP → PDP → ARM pipeline...")
    test_cmd = [
        "python", "PEP.py", "alice",
        "s3:GetObject", "arn:aws:s3:::secure-bucket",
        "192.168.1.12", "device-laptop-001"
    ]
    run_module(test_cmd, "Access Enforcement Chain")

    # 4️⃣  View current metrics
    snapshot = get_metrics_snapshot()
    print("\n📊 Framework Metrics Summary:")
    for k, v in snapshot.items():
        print(f" - {k}: {v}")

    print("\n✅ Framework run complete at", dt.datetime.now().isoformat())

if __name__ == "__main__":
    main()
