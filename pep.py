#!/usr/bin/env python3
"""
Final Robust Policy Enforcement Point (PEP)
Compatible with hybrid PDP and mock ARM.
"""

import subprocess
import sys
import json
import datetime as dt
import re
from arm import auto_remediate  
from monitoring import log_event  # Ensure monitoring.py is in the same folder


def extract_decision_and_reason(output):
    """Extracts decision (ALLOW/DENY/REVIEW) and reason from PDP output."""
    clean_output = output.encode("ascii", "ignore").decode("ascii")
    decision_match = re.search(r"\b(ALLOW|DENY|REVIEW)\b", clean_output, re.IGNORECASE)
    reason_match = re.search(r"Reason:\s*(.*)", clean_output, re.IGNORECASE | re.DOTALL)

    decision = decision_match.group(1).upper() if decision_match else "DENY"
    reason = reason_match.group(1).strip() if reason_match else "Unknown"
    return decision, reason


def enforce_access(user, action, resource, ip, device):
    # Call PDP
    result = subprocess.run(
        [sys.executable, "-u", "pdp.py", user, action, resource, ip, device],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    print("=== Raw PDP Output ===")
    print(result.stdout)
    print("======================")

    output = result.stdout.strip()
    decision, reason = extract_decision_and_reason(output)

    # Determine cloud for logging and ARM
    cloud_target = (
        "AWS" if "aws" in resource.lower()
        else "Azure" if "azure" in resource.lower()
        else "GCP"
    )

    # Log access request to monitoring module
    log_event(
        module="PEP",
        event_type="ACCESS_REQUEST",
        user=user,
        resource=resource,
        cloud=cloud_target,
        decision=decision,
        reason=reason
    )

    print(f"[PEP] Access request by {user} for {resource} -> {decision} ({reason})")

    if decision == "DENY":
        print("[PEP] Request blocked ❌")
    elif decision == "REVIEW":
        print("[PEP] Access under manual review ⚠️")
    else:
        print("[PEP] Access granted ✅")

    # Trigger Auto Remediation if needed
    if decision in ["DENY", "REVIEW"]:
        auto_remediate(user, resource, decision, reason, cloud_target)


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python pep.py <user> <action> <resource> <ip> <device>")
        sys.exit(1)

    _, user, action, resource, ip, device = sys.argv
    enforce_access(user, action, resource, ip, device)
