import boto3 # type: ignore
import csv
import sys
import datetime as dt
from typing import List, Dict, Any

def to_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]

def normalize_statements(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    stm = doc.get("Statement", [])
    if isinstance(stm, dict):
        return [stm]
    return stm

ESCALATIONS_ACTIONS = {
    "Iam:passrole","iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:putrolepolicy", "iam:attachrolepolicy", "iam:attachuserpolicy"
}

def check_policy_doc(doc: Dict[str, Any]) -> List[str]:
    findings = []
    for s in normalize_statements(doc):
        actions = to_list(s.get("Action"))
        resources = to_list(s.get("Resource"))

        actions_l = [a.lower() if isinstance(a, str) else str(a).lower for a in actions]
        resources_l = [r for r in resources]

        if any(a == "*" for a in actions_l):
            if any(r == "*" for r in resources_l):
                findings.append("Policy allows '*' actions on '*' resources.")
            if any(r == "*" for r in resources_l):
                findings.append("wildcard resource")
            if any(a.endswith(":*") for a in actions_l):
                findings.append("wildcard_action_prefix")
            if any(a in ESCALATIONS_ACTIONS for a in actions_l):
                findings.append("privilege_escalation_action")
        return list(set(findings))

def scan_iam(output_csv = "findings.csv"):
    iam = boto3.client("iam")

    rows = []
    timestamp = dt.datetime.utcnow().isoformat()

    print("[*] Scanning IAM Policies...")
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for pol in page.get("Policies", []):
            arn = pol.get("Arn")
            name = pol.get("PolicyName")
            try:
                ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                doc = iam.get_policy_version(PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]  
                findings = check_policy_doc(doc)
                for f in findings:
                    rows.append({
                        "timestamp": timestamp,
                        "resource_type": "ManagedPolicy",
                        "resource_name": name,
                        "resource_arn": arn,
                        "finding": f
                    })
            except Exception as e:
                print(f"[!] Error processing policy {name} ({arn}): {e}", file=sys.stderr)
    print("[*] Checking users for inline policies and old access keys...")
    users = iam.list_users().get("Users", [])
    for u in users:
        user_name = u.get("UserName")
        try:
            inline_names = iam.list_user_policies(UserName=user_name).get("PolicyNames", [])
            for pname in inline_names:
                doc = iam.get_user_policy(UserName=user_name, PolicyName=pname)["PolicyDocument"]
                findings = check_policy_doc(doc)
                for f in findings:
                    rows.append({
                        "timestamp": timestamp,
                        "resource_type": "InlineUserPolicy",
                        "resource_name": f"{user_name}/{pname}",
                        "resource_arn": f"arn:aws:iam::{u.get('UserId')}:user/{user_name}/policy/{pname}",
                        "finding": "inline_policy_on_user"
                    })
            keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            for k in keys:
                create_dt = k.get("CreateDate")
                if create_dt:
                    age_days = (dt.datetime.now(dt.timezone.utc) - create_dt).days
                    if age_days > 90:
                        rows.append({
                            "timestamp": timestamp,
                            "resource_type": "AccessKey",
                            "resource_name": f"{user_name}/{k.get('AccessKeyId')}",
                            "resource_arn": "arn:aws:iam::{u.get('UserId')}:user/{user_name}/accesskey/{k.get('AccessKeyId')}",
                            "finding": "old_access_key"
                        })
        except Exception as e:
            print(f"[!] Error processing user {user_name}: {e}", file=sys.stderr)

    keys = ["timestamp", "resource_type", "resource_name", "resource_arn", "finding"]
    with open(output_csv, "w", newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    
    print(f"[*] Scan complete. Findings written to {output_csv}")
    for r in rows:
        print(f"{r['resource_type']} - {r['resource_name']} -> {r['finding']}")


if __name__ == "__main__":
    scan_iam()
