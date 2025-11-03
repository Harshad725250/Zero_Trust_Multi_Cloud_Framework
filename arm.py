# arm.py
import json
from datetime import datetime as dt

# Mock multi-cloud adapters
def aws_revoke_access(user):
    # Mock AWS remediation
    # Replace this with actual boto3 code if boto3 is installed
    try:
        # Simulate removing user from risky group
        return f"Removed {user} from SensitiveAccess group in AWS (mock)"
    except Exception as e:
        return f"AWS Remediation failed: {e}"

def azure_revoke_access(user):
    # Placeholder: call Azure SDK to remove user from risky role
    return f"Azure remediation triggered for {user}"

def gcp_revoke_access(user):
    # Placeholder: call GCP IAM API to revoke roles
    return f"GCP remediation triggered for {user}"

def log_remediation(entry):
    with open("arm_log.json", "a") as f:
        f.write(json.dumps(entry) + "\n")

def auto_remediate(user, resource, decision, reason, cloud):
    timestamp = dt.utcnow().isoformat()
    actions = []

    if decision == "DENY":
        if "aws" in cloud.lower():
            actions.append(aws_revoke_access(user))
        elif "azure" in cloud.lower():
            actions.append(azure_revoke_access(user))
        elif "gcp" in cloud.lower():
            actions.append(gcp_revoke_access(user))
    elif decision == "REVIEW":
        # For review, just notify/admin log
        actions.append(f"Admin review needed for {user} on {resource}: {reason}")

    log_entry = {
        "timestamp": timestamp,
        "user": user,
        "resource": resource,
        "decision": decision,
        "reason": reason,
        "cloud": cloud,
        "actions_taken": actions
    }

    log_remediation(log_entry)
    print(f"[ARM] Auto-Remediation Log: {log_entry}")
