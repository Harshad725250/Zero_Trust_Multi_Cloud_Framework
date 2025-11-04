#!/usr/bin/env python3
"""
Evaluation Script for Zero Trust Multi-Cloud Framework
------------------------------------------------------
Generates accuracy metrics and confusion matrix for PDP decisions.
"""

import json
import os
from sklearn.metrics import confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns

LOG_FILE = "ztmc_framework_log.json"

# Ground truth expected results for the simulated users/actions
GROUND_TRUTH = {
    "alice": "ALLOW",
    "bob": "DENY",
    "charlie": "DENY",   # borderline (expected ALLOW earlier, we test detection strictness)
    "david": "DENY",
    "eve": "DENY",
    "frank": "REVIEW",   # unknown device but inside trusted subnet (borderline)
    "grace": "ALLOW",    # trusted subnet + valid action
    "heidi": "DENY",     # valid subnet but invalid action
    "ivan": "REVIEW",    # partially valid context
    "judy": "DENY"       # completely untrusted
}

def load_log(file_path):
    """Load PDP decision events from log file."""
    if not os.path.exists(file_path):
        print("[!] Log file not found.")
        return []

    with open(file_path, "r") as f:
        lines = [json.loads(line) for line in f if line.strip()]

    # Extract only PDP decision-type entries
    return [e for e in lines if e.get("decision")]

def evaluate_pdp_accuracy(events):
    """Compare PDP decisions to expected outcomes."""
    y_true, y_pred = [], []

    for e in events:
        user = e.get("user")
        decision = e.get("decision")
        if user in GROUND_TRUTH:
            y_true.append(GROUND_TRUTH[user])
            y_pred.append(decision)

    if not y_true:
        print("[!] No matching ground truth found in log.")
        return

    print("\n=== Evaluation Report ===")
    print(classification_report(y_true, y_pred, digits=3, zero_division=0))


    cm = confusion_matrix(y_true, y_pred, labels=["ALLOW", "DENY", "REVIEW"])
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=["ALLOW", "DENY", "REVIEW"],
                yticklabels=["ALLOW", "DENY", "REVIEW"])
    plt.xlabel("Predicted")
    plt.ylabel("Expected")
    plt.title("Confusion Matrix - PDP Decision Accuracy")
    plt.tight_layout()
    plt.show()

def main():
    events = load_log(LOG_FILE)
    if events:
        evaluate_pdp_accuracy(events)
    else:
        print("No PDP decisions to evaluate.")

if __name__ == "__main__":
    main()
