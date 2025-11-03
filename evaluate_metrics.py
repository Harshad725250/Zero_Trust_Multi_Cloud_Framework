#!/usr/bin/env python3
"""
Evaluation Metrics Analyzer for Zero Trust Multi-Cloud Framework
---------------------------------------------------------------
Aggregates and analyzes logs from:
 - IaC Auditor (iac_findings.csv)
 - PDP (pdp_decisions.csv)
 - PEP (pep_log.json)
 - Auto-Remediation (arm_log.json)
 - Central Monitoring (ztmc_framework_log.json)

Generates:
 - Metric summary (printed + saved)
 - Visual graphs (bar/pie charts)
"""

import csv
import json
import os
import statistics
from datetime import datetime as dt
import matplotlib.pyplot as plt # type: ignore

# -----------------------------
# File Paths
# -----------------------------
IAC_FILE = "iac_findings.csv"
PDP_FILE = "pdp_decisions.csv"
PEP_FILE = "pep_log.json"
ARM_FILE = "arm_log.json"
LOG_FILE = "ztmc_framework_log.json"

REPORT_FILE = "evaluation_report.txt"

# -----------------------------
# Helper Functions
# -----------------------------
def read_csv(file):
    data = []
    if not os.path.exists(file):
        return data
    with open(file, "r") as f:
        reader = csv.DictReader(f)
        data = list(reader)
    return data

def read_json_lines(file):
    data = []
    if not os.path.exists(file):
        return data
    with open(file, "r") as f:
        for line in f:
            try:
                data.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    return data

def avg_time_difference(timestamps):
    """Computes average time gap between sequential timestamps."""
    try:
        times = [dt.fromisoformat(t) for t in timestamps if t]
        diffs = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
        return round(statistics.mean(diffs), 3) if diffs else 0
    except Exception:
        return 0

# -----------------------------
# Metric Calculations
# -----------------------------
def calculate_iac_metrics(iac_data):
    total_findings = len(iac_data)
    s3 = sum(1 for f in iac_data if "S3" in f.get("finding", ""))
    sg = sum(1 for f in iac_data if "Security group" in f.get("finding", ""))
    iam = sum(1 for f in iac_data if "IAM" in f.get("finding", ""))
    return {
        "Total Findings": total_findings,
        "S3 Issues": s3,
        "Security Group Issues": sg,
        "IAM Policy Issues": iam
    }

def calculate_pdp_metrics(pdp_data):
    total = len(pdp_data)
    allow = sum(1 for r in pdp_data if r["decision"].lower() == "allow")
    deny = sum(1 for r in pdp_data if r["decision"].lower() == "deny")
    review = sum(1 for r in pdp_data if r["decision"].lower() == "review")
    avg_gap = avg_time_difference([r["timestamp"] for r in pdp_data])
    return {
        "Total Decisions": total,
        "Allow": allow,
        "Deny": deny,
        "Review": review,
        "Avg Decision Interval (s)": avg_gap
    }

def calculate_pep_metrics(pep_data):
    total = len(pep_data)
    allow = sum(1 for e in pep_data if e["decision"].upper() == "ALLOW")
    deny = sum(1 for e in pep_data if e["decision"].upper() == "DENY")
    review = sum(1 for e in pep_data if e["decision"].upper() == "REVIEW")
    return {
        "Total Access Requests": total,
        "Allow": allow,
        "Deny": deny,
        "Review": review
    }

def calculate_arm_metrics(arm_data):
    total = len(arm_data)
    deny = sum(1 for a in arm_data if a["decision"] == "DENY")
    review = sum(1 for a in arm_data if a["decision"] == "REVIEW")
    clouds = set(a["cloud"] for a in arm_data if "cloud" in a)
    return {
        "Total Remediations": total,
        "Deny Remediations": deny,
        "Review Remediations": review,
        "Clouds Covered": len(clouds)
    }

def calculate_log_metrics(log_data):
    total = len(log_data)
    per_module = {}
    for entry in log_data:
        mod = entry.get("module", "Unknown")
        per_module[mod] = per_module.get(mod, 0) + 1
    return {
        "Total Logged Events": total,
        "Events Per Module": per_module
    }

# -----------------------------
# Visualization
# -----------------------------
def plot_metrics(metrics_dict, title, filename):
    plt.figure(figsize=(8, 5))
    plt.bar(metrics_dict.keys(), metrics_dict.values())
    plt.title(title)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

# -----------------------------
# Main Aggregator
# -----------------------------
def main():
    print("[*] Loading module data...")

    iac = read_csv(IAC_FILE)
    pdp = read_csv(PDP_FILE)
    pep = read_json_lines(PEP_FILE)
    arm = read_json_lines(ARM_FILE)
    log = read_json_lines(LOG_FILE)

    print("[*] Calculating metrics...")

    iac_m = calculate_iac_metrics(iac)
    pdp_m = calculate_pdp_metrics(pdp)
    pep_m = calculate_pep_metrics(pep)
    arm_m = calculate_arm_metrics(arm)
    log_m = calculate_log_metrics(log)

    # Write Report
    with open(REPORT_FILE, "w") as f:
        f.write("=== Zero Trust Multi-Cloud Framework Evaluation Report ===\n\n")
        for section, metrics in [
            ("IaC Auditor", iac_m),
            ("Policy Decision Point (PDP)", pdp_m),
            ("Policy Enforcement Point (PEP)", pep_m),
            ("Auto Remediation Module", arm_m),
            ("Central Monitoring", log_m)
        ]:
            f.write(f"--- {section} ---\n")
            for k, v in metrics.items():
                f.write(f"{k}: {v}\n")
            f.write("\n")

    print(f"[*] Evaluation complete. Report written to {REPORT_FILE}")

    # Plot visual summaries
    plot_metrics(iac_m, "IaC Misconfiguration Breakdown", "iac_metrics.png")
    plot_metrics(pdp_m, "PDP Decision Distribution", "pdp_metrics.png")
    plot_metrics(pep_m, "PEP Access Request Summary", "pep_metrics.png")
    plot_metrics(arm_m, "Auto Remediation Summary", "arm_metrics.png")

    print("[*] Graphs saved (iac_metrics.png, pdp_metrics.png, pep_metrics.png, arm_metrics.png)")

if __name__ == "__main__":
    main()
