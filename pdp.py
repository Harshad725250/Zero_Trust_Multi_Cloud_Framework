#!/usr/bin/env python3
"""
Hybrid Context + Policy-Based PDP
Evaluates:
 - Action policies (from policies.json)
 - Context policies (IP, device, time)
Combines both to enforce Zero Trust access decisions
"""

import json
import csv
import datetime as dt
import sys


POLICY_FILE = "policies.json"
OUTPUT_LOG = "pdp_decisions.csv"

# Context configuration
TRUSTED_IP_RANGES = ["192.168.", "10.0."]
TRUSTED_DEVICES = ["device-laptop-001", "device-admin-001"]
BUSINESS_HOURS = (8, 20)  # 8 AM – 8 PM

def load_policies():
    with open(POLICY_FILE, "r") as f:
        return json.load(f)

def in_trusted_network(ip):
    return any(ip.startswith(prefix) for prefix in TRUSTED_IP_RANGES)

def within_business_hours():
    now = dt.datetime.now().hour
    return BUSINESS_HOURS[0] <= now < BUSINESS_HOURS[1]

def is_trusted_device(device_id):
    return device_id in TRUSTED_DEVICES

def evaluate_context(request):
    """Evaluates context rules"""
    ip = request.get("ip", "unknown")
    device = request.get("device", "unknown")

    # Contextual checks
    if not in_trusted_network(ip):
        return "deny", f"Untrusted network source ({ip})"
    if not within_business_hours():
        return "deny", "Access attempted outside business hours"
    if not is_trusted_device(device):
        return "review", f"Unrecognized device ({device})"
    return "allow", "Context validated"

def evaluate_action(request, policy_data):
    """Evaluates static action-based policies"""
    action = request.get("action", "").lower()
    for p in policy_data["policies"]:
        actions = [a.lower() for a in p["conditions"].get("action", [])]
        if action in actions or "*" in actions:
            return p["decision"], p["description"]
    return policy_data.get("default_action", "deny"), "No matching policy (default deny)"

def combine_decisions(context_decision, action_decision):
    """Combines contextual and policy-based outcomes"""
    # Deny overrides everything (Zero Trust principle)
    if "deny" in (context_decision, action_decision):
        return "deny"
    # Review if context is uncertain but action is allowed
    if context_decision == "review" and action_decision == "allow":
        return "review"
    # Allow only if both are clean
    if context_decision == "allow" and action_decision == "allow":
        return "allow"
    # Default fallback
    return "deny"

def log_decision(result):
    keys = ["timestamp", "user", "action", "resource", "ip", "device", "decision", "reason"]
    with open(OUTPUT_LOG, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        if f.tell() == 0:
            writer.writeheader()
        writer.writerow(result)

def main():
    if len(sys.argv) != 6:
        print("Usage: python pdp.py <user> <action> <resource> <ip> <device>")
        sys.exit(1)

    user, action, resource, ip, device = sys.argv[1:]
    request = {"user": user, "action": action, "resource": resource, "ip": ip, "device": device}

    # Load and evaluate
    policy_data = load_policies()
    context_decision, context_reason = evaluate_context(request)
    action_decision, action_reason = evaluate_action(request, policy_data)
    final_decision = combine_decisions(context_decision, action_decision)

    # Pick most relevant reason
    reason = (
        context_reason if final_decision == context_decision else action_reason
    )

    result = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "user": user,
        "action": action,
        "resource": resource,
        "ip": ip,
        "device": device,
        "decision": final_decision,
        "reason": reason,
    }

    log_decision(result)
    print(f"[PDP] Decision for {user} -> {final_decision.upper()} (Reason: {reason})", flush=True)



if __name__ == "__main__":
    main()
