def merge_findings(semgrep_findings, trivy_findings, gitleaks_findings):
    seen = {}
    all_findings = semgrep_findings + trivy_findings + gitleaks_findings

    for finding in all_findings:
        fp = finding.fingerprint

        if fp not in seen:
            seen[fp] = finding

    deduped_findings = list(seen.values())

    deduped_findings.sort(key=lambda f: f.severity_rank())

    return deduped_findings