import json
import sys

GATE_INFO = {
    "gatr-01": ("High Vulnerability", "Security", "NON_ENFORCING", "Snyk", "Yes"),
    "gatr-02": ("Medium Vulnerability", "Security", "NON_ENFORCING", "Snyk", "Yes"),
    "gatr-03": ("Critical Vulnerability", "Security", "NON_ENFORCING", "Snyk", "Yes"),
    "gatr-07": ("Developer Thresholds", "Quality", "NON_ENFORCING", "SonarQube", "Yes"),
    "gatr-08": ("Code Quality", "Quality", "ENFORCING", "SonarQube", "Yes"),
    "gatr-09": ("Approved Sonar Params", "Quality", "ENFORCING", "GitHub Actions", "No"),
    "gatr-10": ("Express Lane Quality", "Quality", "NON_ENFORCING", "SonarQube", "Yes"),
    "gatr-14": ("Release Branch", "Governance", "ENFORCING", "GitHub Actions", "No"),
}

def main():
    if len(sys.argv) < 2:
        print("ERROR: Missing gate-result.json path", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]

    with open(path) as f:
        data = json.load(f)

    for g in data["gates"]:
        gid = g["id"]
        label = GATE_INFO.get(gid, ("Unknown", "Unknown", "Unknown", "Unknown", "Unknown"))
        print(f"| {gid} | {label[0]} | {label[1]} | {label[2]} | {label[3]} | {label[4]} | {g['status']} |")

if __name__ == "__main__":
    main()
