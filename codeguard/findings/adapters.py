
from .schema import SEVERITY_MAP, Finding, Severity, FindingType

def from_semgrep(semgrep_scan_results):
    findings = []

    results_list = semgrep_scan_results.get("results", [])

    for result in results_list:
        result_extra = result.get("extra", {})
        result_metadata = result_extra.get("metadata", {})

        raw_severity = result_extra.get("severity", "INFO")
        normalized_severity = SEVERITY_MAP.get(raw_severity.upper(), Severity.INFO)

        title = result["check_id"].split(".")[-1]
        description = result_extra.get("message", "")
        file_path = result.get("path")

        start_data = result.get("start", {})
        end_data = result.get("end", {})
        start_line = start_data.get("line")
        end_line = end_data.get("line")

        rule_id = result.get("check_id")
        cwe_ids = result_metadata.get("cwe", [])
        references = result_metadata.get("references", [])

        finding = Finding(
            tool="semgrep",
            finding_type=FindingType.SAST,
            severity=normalized_severity,
            title=title,
            description=description,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            rule_id=rule_id,
            cwe_ids=cwe_ids,
            references=references,
            raw=result,
        )

        findings.append(finding)

    return findings



            
        
    
def from_trivy(trivy_scan_results):
    findings = []

    results_list = trivy_scan_results.get("Results", [])

    for result in results_list:
        file_path = result.get("Target")

        vuln_list = result.get("Vulnerabilities") or []
        for vuln in vuln_list:
            raw_severity = vuln.get("Severity", "UNKNOWN")
            normalized_severity = SEVERITY_MAP.get(raw_severity.upper(), Severity.INFO)

            finding = Finding(
                tool="trivy",
                finding_type=FindingType.DEPENDENCY,
                severity=normalized_severity,
                title=vuln.get("VulnerabilityID"),
                description=vuln.get("Title", ""),
                file_path=file_path,
                rule_id=vuln.get("VulnerabilityID"),
                cve_id=vuln.get("VulnerabilityID"),
                cwe_ids=vuln.get("CweIDs", []),
                package_name=vuln.get("PkgName"),
                installed_version=vuln.get("InstalledVersion"),
                fixed_version=vuln.get("FixedVersion"),
                references=vuln.get("References", []),
                raw=vuln,
            )
            findings.append(finding)

        misconfig_list = result.get("Misconfigurations") or []
        for misconfig in misconfig_list:
            raw_severity = misconfig.get("Severity", "UNKNOWN")
            normalized_severity = SEVERITY_MAP.get(raw_severity.upper(), Severity.INFO)

            finding = Finding(
                tool="trivy",
                finding_type=FindingType.MISCONFIG,
                severity=normalized_severity,
                title=misconfig.get("Title"),
                description=misconfig.get("Message", ""),
                file_path=file_path,
                rule_id=misconfig.get("ID"),
                raw=misconfig,
            )
            findings.append(finding)

    return findings

def from_gitleaks(gitleaks_scan_results):
    findings = []

    if not gitleaks_scan_results:
        return findings

    for leak in gitleaks_scan_results:

        finding = Finding(
            tool="gitleaks",
            finding_type= FindingType.SECRET,
            severity=Severity.CRITICAL,
            title=leak.get("Description","Secret detected"),
            description=f"Rule: {leak.get('RuleID')}",
            file_path=leak.get("File"),
            start_line=leak.get("StartLine"),
            end_line=leak.get("EndLine"),
            rule_id=leak.get("RuleID"),
            commit=leak.get("Commit"),
            author=leak.get("Author"),
            raw=leak
        )

        findings.append(finding)

    return findings    