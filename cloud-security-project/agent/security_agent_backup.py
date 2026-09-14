import csv
import glob
import os

# Find Prowler CSV files
files = glob.glob("output/*.csv")

if not files:
    print("No Prowler CSV file found.")
    exit()

# Use the latest CSV file
prowler_file = max(files, key=os.path.getmtime)

print("Reading Prowler report:")
print(prowler_file)
print()

# Read the CSV file
with open(prowler_file, "r", encoding="utf-8") as file:
    reader = csv.DictReader(file, delimiter=";")

    findings = []

    for row in reader:
        if row.get("STATUS") == "FAIL":
            findings.append({
                "check_id": row.get("CHECK_ID"),
                "title": row.get("CHECK_TITLE"),
                "severity": row.get("SEVERITY"),
                "resource": row.get("RESOURCE_UID")
            })

# Display the findings
print("Security Findings:")
print("==================")

for finding in findings:
    print(f"Check ID : {finding['check_id']}")
    print(f"Title    : {finding['title']}")
    print(f"Severity : {finding['severity']}")
    print(f"Resource : {finding['resource']}")
    print("------------------")

print(f"\nTotal failed findings: {len(findings)}")
