# monitoring.py
"""
Centralized Logging and Monitoring for Zero Trust Multi-Cloud Framework
"""

import json
from datetime import datetime as dt
from threading import Lock

# Thread-safe counters
monitoring_lock = Lock()

# Monitoring metrics
metrics = {
    "total_access_requests": 0,
    "deny_count": 0,
    "review_count": 0,
    "allow_count": 0,
    "total_remediations": 0,
    "per_cloud": {"AWS": 0, "Azure": 0, "GCP": 0},
    "events_by_type": {}
}

# Central log file
LOG_FILE = "ztmc_framework_log.json"
METRICS_FILE = "ztmc_framework_metrics.json"

# -----------------------------
# Logging function
# -----------------------------
def log_event(module, event_type, user, resource, cloud, decision=None, reason=None, actions=None, details=None):
    """
    Logs an event from any module.
    module: source module name (PEP, PDP, ARM, IAM, IaC)
    event_type: type of event (ACCESS_REQUEST, POLICY_CHANGE, REMEDIATION, etc.)
    decision: DENY/ALLOW/REVIEW if relevant
    """
    timestamp = dt.utcnow().isoformat()
    entry = {
        "timestamp": timestamp,
        "module": module,
        "event_type": event_type,
        "user": user,
        "resource": resource,
        "cloud": cloud,
        "decision": decision,
        "reason": reason,
        "actions_taken": actions or [],
        "details": details or {}
    }

    # Write to log file
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

    # Update metrics
    update_metrics(entry)

# -----------------------------
# Metrics updater
# -----------------------------
def update_metrics(entry):
    with monitoring_lock:
        metrics["total_access_requests"] += 1 if entry["event_type"] == "ACCESS_REQUEST" else 0
        metrics["total_remediations"] += 1 if entry["event_type"] == "REMEDIATION" else 0

        # Count by decision
        if entry.get("decision") == "DENY":
            metrics["deny_count"] += 1
        elif entry.get("decision") == "REVIEW":
            metrics["review_count"] += 1
        elif entry.get("decision") == "ALLOW":
            metrics["allow_count"] += 1

        # Count per cloud
        cloud = entry.get("cloud")
        if cloud in metrics["per_cloud"]:
            metrics["per_cloud"][cloud] += 1

        # Count events by type
        event_type = entry.get("event_type")
        metrics["events_by_type"].setdefault(event_type, 0)
        metrics["events_by_type"][event_type] += 1

        # Save metrics
        with open(METRICS_FILE, "w") as f:
            f.write(json.dumps(metrics, indent=2))

# -----------------------------
# Function to push metrics snapshot
# -----------------------------
def get_metrics_snapshot():
    with monitoring_lock:
        return metrics.copy()
