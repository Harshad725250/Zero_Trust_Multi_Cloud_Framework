#!/usr/bin/env python3
"""
Zero Trust Multi-Cloud Framework: Metrics Aggregator
----------------------------------------------------
Aggregates data from PDP, PEP, ARM, IAM, and IaC modules
and generates consolidated performance and security metrics
for research evaluation.

Outputs:
 - ztmc_summary_metrics.json
 - ztmc_comparative_metrics.csv
 - charts/*.png
"""

import json
import csv
import datetime as dt
from collections import Counter, defaultdict
import matplotlib.pyplot as plt # type: ignore
import os

# Input files (ensure they exist)
FILES = {
    "PDP": "pdp_decisions.csv",
    "MONITOR": "ztmc_framework_log.json",
    "IAM": "findings.csv",
    "IAC": "iac_findings.csv",
    "ARM": "arm_log.json"
}

OUTPUT_JSON = "ztmc_summary_metrics.json"
OUTPUT_CSV = "ztmc_comparative_metrics.csv"
CHART_DIR = "charts"
os.makedirs(CHART_DIR, exist_ok=True)

# -------------------------------
# Utility functions
# -------------------------------
def safe_load_jsonl(path):
    if not os.path.exists(path): return []
    data = []
    with open(path) as f:
        for line in f:
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return data

def safe_load_csv(path):
    if not os.path.exists(path): return []
    with open(path) as f:
        reader = csv.DictReader(f)
        return [r for r in reader]

# -------------------------------
# Load all module data
# -------------------------------
pdp_data = safe_load_csv(FILES["PDP"])
monitor_data = safe_load_jsonl(FILES["MONITOR"])
iam_data = safe_load_csv(FILES["IAM"])
iac_data = safe_load_csv(FILES["IAC"])
arm_data = safe_load_jsonl(FILES["ARM"])

# -------------------------------
# Compute metrics
# -------------------------------
summary = {}

# PDP Metrics
decisions = Counter([r["decision"].upper() for r in pdp_data if r.get("decision")])
summary["pdp_decisions"] = dict(decisions)
summary["total_requests"] = sum(decisions.values())

# IAM Findings
iam_findings = Counter([r["finding"] for r in iam_data if r.get("finding")])
summary["iam_findings"] = dict(iam_findings)
summary["total_iam_findings"] = sum(iam_findings.values())

# IaC Findings
iac_findings = Counter([r["finding"] for r in iac_data if len(r) > 2])
summary["iac_findings"] = dict(iac_findings)
summary["total_iac_findings"] = sum(iac_findings.values())

# Auto Remediation
arm_actions = Counter()
for entry in arm_data:
    for a in entry.get("actions_taken", []):
        if "AWS" in a: arm_actions["AWS"] += 1
        elif "Azure" in a: arm_actions["Azure"] += 1
        elif "GCP" in a: arm_actions["GCP"] += 1
summary["auto_remediations"] = dict(arm_actions)
summary["total_remediations"] = sum(arm_actions.values())

# Monitoring Metrics (events)
event_types = Counter([r.get("event_type") for r in monitor_data if r.get("event_type")])
summary["monitoring_events"] = dict(event_types)

# -------------------------------
# Derived research metrics
# -------------------------------
def calc_percent(part, total):
    return round((part / total) * 100, 2) if total > 0 else 0

summary["deny_rate_%"] = calc_percent(decisions.get("DENY", 0), summary["total_requests"])
summary["allow_rate_%"] = calc_percent(decisions.get("ALLOW", 0), summary["total_requests"])
summary["review_rate_%"] = calc_percent(decisions.get("REVIEW", 0), summary["total_requests"])
summary["risk_reduction_factor"] = calc_percent(
    summary["total_iam_findings"] + summary["total_iac_findings"] - summary["total_remediations"],
    summary["total_iam_findings"] + summary["total_iac_findings"]
)

# -------------------------------
# Export consolidated metrics
# -------------------------------
with open(OUTPUT_JSON, "w") as f:
    json.dump(summary, f, indent=2)

# Also export comparison-friendly CSV
with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Metric", "Value"])
    for k, v in summary.items():
        if not isinstance(v, (dict, list)):
            writer.writerow([k, v])

print(f"[*] Consolidated metrics written to {OUTPUT_JSON} and {OUTPUT_CSV}")

# -------------------------------
# Visualization Section
# -------------------------------
# 1. PDP Decision Distribution
plt.figure(figsize=(5, 5))
plt.pie(decisions.values(), labels=decisions.keys(), autopct="%1.1f%%")
plt.title("Access Decision Distribution (PDP)")
plt.savefig(os.path.join(CHART_DIR, "pdp_decisions.png"))
plt.close()

# 2. IAM Findings
if iam_findings:
    plt.figure(figsize=(7, 4))
    plt.bar(iam_findings.keys(), iam_findings.values())
    plt.xticks(rotation=45, ha="right")
    plt.title("IAM Findings by Type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, "iam_findings.png"))
    plt.close()

# 3. IaC Findings
if iac_findings:
    plt.figure(figsize=(7, 4))
    plt.bar(iac_findings.keys(), iac_findings.values(), color="orange")
    plt.xticks(rotation=45, ha="right")
    plt.title("IaC Misconfigurations Detected")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, "iac_findings.png"))
    plt.close()

# 4. Auto Remediation Actions
if arm_actions:
    plt.figure(figsize=(5, 4))
    plt.bar(arm_actions.keys(), arm_actions.values(), color="green")
    plt.title("Auto-Remediation Actions per Cloud")
    plt.ylabel("Actions Taken")
    plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, "auto_remediation.png"))
    plt.close()

# 5. Event Types
if event_types:
    plt.figure(figsize=(7, 4))
    plt.bar(event_types.keys(), event_types.values(), color="purple")
    plt.title("Events Logged by Monitoring System")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, "event_types.png"))
    plt.close()

print(f"[*] Charts generated in '{CHART_DIR}/'")
