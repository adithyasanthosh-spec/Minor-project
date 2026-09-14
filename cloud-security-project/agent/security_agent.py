import csv
import glob
import os
import boto3
from datetime import datetime

files = glob.glob("output/*.csv")

if not files:
    print("No Prowler CSV file found.")
    exit()

prowler_file = max(files, key=os.path.getmtime)

print("Reading Prowler report:")
print(prowler_file)
print()

ec2 = boto3.client("ec2", region_name="eu-north-1")

log_file = "agent/logs/audit_log.csv"

with open(prowler_file, "r", encoding="utf-8") as file:
    reader = csv.DictReader(file, delimiter=";")

    findings = []

    for row in reader:
        if row.get("STATUS") == "FAIL":
            severity = row.get("SEVERITY", "").lower()
            check_id = row.get("CHECK_ID")
            resource = row.get("RESOURCE_UID", "")
            title = row.get("CHECK_TITLE")

            if severity == "low":
                decision = "AUTO_REMEDIATE"
            else:
                decision = "HUMAN_APPROVAL"

            action = "No action"
            result = "Pending"

            if (
                check_id == "ec2_instance_detailed_monitoring_enabled"
                and decision == "AUTO_REMEDIATE"
            ):
                instance_id = resource.split("/")[-1]

                print("Action   : Enabling EC2 detailed monitoring...")

                try:
                    ec2.monitor_instances(
                        InstanceIds=[instance_id]
                    )
                    action = "Enabled EC2 detailed monitoring"
                    result = "Success"
                    print("Result   : Remediation successful")
                except Exception as error:
                    action = "Enable EC2 detailed monitoring"
                    result = "Failed"
                    print("Result   : Remediation failed")
                    print(f"Error    : {error}")

            elif decision == "HUMAN_APPROVAL":
                action = "Waiting for human approval"
                result = "Pending"

            with open(log_file, "a", newline="", encoding="utf-8") as log:
                writer = csv.writer(log)
                writer.writerow([
                    datetime.now().isoformat(),
                    check_id,
                    title,
                    severity,
                    decision,
                    action,
                    result,
                    resource
                ])

            findings.append({
                "check_id": check_id,
                "title": title,
                "severity": severity,
                "resource": resource,
                "decision": decision
            })

            print(f"Check ID : {check_id}")
            print(f"Title    : {title}")
            print(f"Severity : {severity}")
            print(f"Decision : {decision}")
            print(f"Action   : {action}")
            print(f"Result   : {result}")
            print("--------------------------------")

print(f"\nTotal failed findings: {len(findings)}")
print(f"Audit log saved to: {log_file}")

