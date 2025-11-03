#!/usr/bin/env python3
"""
generate_access_logs.py
-----------------------
Simulates cloud access events for PDP/PEP testing.

Each entry: timestamp, user, action, resource, ip, device, should_be_allowed
"""

import csv, random, time, datetime as dt

USERS = ["alice", "bob", "charlie", "david"]
ACTIONS = ["s3:GetObject", "s3:PutObject", "iam:PassRole", "ec2:DescribeInstances"]
IPS = ["192.168.1.12", "8.8.8.8", "10.0.0.7"]
DEVICES = ["device-laptop-001", "device-unknown", "device-admin-001"]

OUT_FILE = "access_events.csv"

def generate(n=200):
    with open(OUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","user","action","resource","ip","device","should_be_allowed"])
        for _ in range(n):
            user = random.choice(USERS)
            action = random.choice(ACTIONS)
            ip = random.choice(IPS)
            device = random.choice(DEVICES)
            resource = "arn:aws:s3:::secure-bucket"
            # Label events: deny if risky action or untrusted ip
            should_be_allowed = not (("iam:PassRole" in action) or (ip.startswith("8.")))
            writer.writerow([dt.datetime.utcnow().isoformat(), user, action, resource, ip, device, int(should_be_allowed)])
    print(f"[+] Generated {n} synthetic access events → {OUT_FILE}")

if __name__ == "__main__":
    generate(300)
