import csv
import glob
import os
import boto3

files = glob.glob("output/*.csv")

if not files:
    print("No Prowler CSV file found.")
    exit()

prowler_file = max(files, key=os.path.getmtime)

print("Reading Prowler report:")
print(prowler_file)
print()

ec2 = boto3.client("ec2", region_name="eu-north-1")

with open(prowler_file, "r", encoding="utf-8") as file:
    reader = csv.DictReader(file, delimiter=";")

    findings = []

    for row in reader:
        if row.get("STATUS") == "FAIL":
            severity = row.get("SEVERITY", "").lower()
            check_id = row.get("CHECK_ID")
            resource = row.get("RESOURCE_UID", "")

            if severity == "low":
                decision = "AUTO_REMEDIATE"
            else:
                decision = "HUMAN_APPROVAL"

            findings.append({
                "check_id": check_id,
                "title": row.get("CHECK_TITLE"),
                "severity": severity,
                "resource": resource,
                "decision": decision
            })

print("Security Findings and Decisions:")
print("================================")

for finding in findings:
    print(f"Check ID : {finding['check_id']}")
    print(f"Title    : {finding['title']}")
    print(f"Severity : {finding['severity']}")
    print(f"Resource : {finding['resource']}")
    print(f"Decision : {finding['decision']}")

    if (
        finding["check_id"] == "ec2_instance_detailed_monitoring_enabled"
        and finding["decision"] == "AUTO_REMEDIATE"
    ):
        instance_id = finding["resource"].split("/")[-1]

        print("Action   : Enabling EC2 detailed monitoring...")

        try:
            ec2.monitor_instances(
                InstanceIds=[instance_id]
            )
            print("Result   : Remediation request successful")
        except Exception as error:
            print("Result   : Remediation failed")
            print(f"Error    : {error}")

    print("--------------------------------")

print(f"\nTotal failed findings: {len(findings)}")
