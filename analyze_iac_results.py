#!/usr/bin/env python3
"""
analyze_iac_results.py
----------------------
Analyzes IaC auditor output (iac_findings.csv)
and visualizes misconfiguration counts by type.
"""

import pandas as pd
import matplotlib.pyplot as plt

CSV_FILE = "iac_findings.csv"

# Load CSV
df = pd.read_csv(CSV_FILE)

# Count findings by type
df["finding_type"] = df["finding"].apply(
    lambda x: "S3 Bucket" if "S3 bucket" in x else
              "Security Group" if "Security group" in x else
              "IAM Policy" if "IAM policy" in x else
              "Other"
)

summary = df["finding_type"].value_counts()

# Print text summary
print("\n=== IaC Misconfiguration Summary ===")
print(summary)
print(f"\nTotal findings: {len(df)}")

# Plot bar chart
summary.plot(kind="bar", title="IaC Misconfigurations by Type", figsize=(8,5))
plt.xlabel("Misconfiguration Type")
plt.ylabel("Count")
plt.tight_layout()
plt.show()
