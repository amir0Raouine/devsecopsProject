
import json
from collections import defaultdict
from pathlib import Path

folder = Path(__file__).resolve().parent

with open(folder / "trivy-sca-report.json", encoding="utf-8") as f:
    report = json.load(f)

groups = defaultdict(list)

for result in report.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        if vuln.get("Severity") not in ("HIGH", "CRITICAL"):
            continue

        key = (
            result["Target"],
            vuln["PkgName"],
            vuln["InstalledVersion"]
        )

        groups[key].append(vuln)

for (target, package, version), vulns in sorted(
    groups.items(), key=lambda item: -len(item[1])
):
    fixes = sorted({
        v["FixedVersion"]
        for v in vulns
        if v.get("FixedVersion")
    })

    critical = sum(v["Severity"] == "CRITICAL" for v in vulns)
    high = sum(v["Severity"] == "HIGH" for v in vulns)

    print(f"\n{package}@{version}")
    print(f"  Fichier : {target}")
    print(f"  CRITICAL : {critical} | HIGH : {high}")
    print(f"  Versions corrigees : {', '.join(fixes) if fixes else 'Non indiquees'}")
