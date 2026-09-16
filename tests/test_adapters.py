from codeguard.findings.adapters import from_semgrep,from_gitleaks,from_trivy
from codeguard.findings.schema import FindingType,Severity

def test_from_semgrep_normal_results():
    sample = {
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                "path": "src/app.py",
                "start": {"line": 10},
                "end": {"line": 10},
                "extra": {
                    "message": "Detected subprocess with shell=True.",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-78"],
                        "references": ["https://example.com/cwe-78"]
                    }
                }
            }
        ]
    }

    findings = from_semgrep(sample)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.finding_type == FindingType.SAST
    assert f.severity == Severity.HIGH
    assert f.title == "dangerous-subprocess-use"
    assert f.description == "Detected subprocess with shell=True."
    assert f.file_path == "src/app.py"
    assert f.start_line == 10
    assert f.end_line == 10
    assert f.rule_id == "python.lang.security.audit.dangerous-subprocess-use"
    assert f.cwe_ids == ["CWE-78"]
    assert f.references == ["https://example.com/cwe-78"]
 
def test_from_semgrep_empty_results_return_empty_list():
    empty_sample = {"results":[]}
    empty_findings = from_semgrep(empty_sample)

    assert empty_findings == []

def test_from_semgrep_missing_optional_results_defaults_safety():
    optional_sample = {
        "results":[
        {
            "check_id": "x.y.z",
            "path": "a.py",
            "start": {"line": 1},
            "end": {"line": 1},
            "extra": {}
        }
        ]
    }

    optional_findings = from_semgrep(optional_sample)

    assert optional_findings[0].cwe_ids == []
    assert optional_findings[0].references == []
    assert optional_findings[0].severity == Severity.INFO


def test_from_trivy_parses_normal_vulnerability():
    normal_sample = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2020-1234",
                        "PkgName": "django",
                        "InstalledVersion": "2.2.0",
                        "FixedVersion": "2.2.28",
                        "Severity": "CRITICAL",
                        "Title": "Django SQL injection",
                        "CweIDs": ["CWE-89"],
                        "References": ["https://example.com/cve"],
                    }
                ],
            }
        ]
    }

    findings = from_trivy(normal_sample)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "trivy"
    assert f.finding_type == FindingType.DEPENDENCY
    assert f.severity == Severity.CRITICAL
    assert f.title == "CVE-2020-1234"
    assert f.description == "Django SQL injection"
    assert f.file_path == "requirements.txt"
    assert f.rule_id == "CVE-2020-1234"
    assert f.cve_id == "CVE-2020-1234"
    assert f.package_name == "django"
    assert f.installed_version == "2.2.0"
    assert f.fixed_version == "2.2.28"
    assert f.cwe_ids == ["CWE-89"]


def test_from_trivy_null_vulnerabilities_returns_empty_list():
    null_sample = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": None}]}
    assert from_trivy(null_sample) == []

def test_from_trivy_null_misconfigurations_returns_empty_list():
    sample = {"Results": [{"Target": "Dockerfile", "Misconfigurations": None}]}
    assert from_trivy(sample) == []


def test_from_trivy_parses_misconfiguration():
    sample = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "Image user should not be 'root'",
                        "Message": "Specify at least 1 USER command",
                        "Severity": "HIGH",
                    }
                ],
            }
        ]
    }

    findings = from_trivy(sample)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "trivy"
    assert f.finding_type == FindingType.MISCONFIG
    assert f.severity == Severity.HIGH
    assert f.title == "Image user should not be 'root'"
    assert f.description == "Specify at least 1 USER command"
    assert f.file_path == "Dockerfile"
    assert f.rule_id == "DS002"


def test_from_trivy_parses_vulns_and_misconfigs_from_same_target():
    sample = {
        "Results": [
            {
                "Target": "mixed-target",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "Severity": "LOW", "Title": "v"}
                ],
                "Misconfigurations": [
                    {"ID": "M-1", "Severity": "MEDIUM", "Title": "m", "Message": ""}
                ],
            }
        ]
    }

    findings = from_trivy(sample)

    assert len(findings) == 2
    types = {f.finding_type for f in findings}
    assert types == {FindingType.DEPENDENCY, FindingType.MISCONFIG}


def test_from_trivy_multiple_targets():
    sample = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "Severity": "HIGH", "Title": ""}
                ],
            },
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2", "Severity": "LOW", "Title": ""}
                ],
            },
        ]
    }

    findings = from_trivy(sample)

    assert len(findings) == 2
    assert {f.file_path for f in findings} == {"requirements.txt", "package-lock.json"}

def test_from_trivy_empty_results_returns_empty_list():
    assert from_trivy({"Results": []}) == []

def test_from_trivy_missing_results_key_returns_empty_list():
    assert from_trivy({}) == []

def test_from_trivy_unknown_severity_falls_back_to_info():
    sample = {
        "Results": [
            {
                "Target": "x",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-X", "Severity": "WEIRD", "Title": ""}
                ],
            }
        ]
    }

    assert from_trivy(sample)[0].severity == Severity.INFO

def test_from_gitleaks_parses_normal_leak():
    sample = [
        {
            "Description": "AWS Access Key",
            "File": ".env",
            "StartLine": 3,
            "EndLine": 3,
            "RuleID": "aws-access-token",
            "Commit": "abc123",
            "Author": "jane",
        }
    ]

    findings = from_gitleaks(sample)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "gitleaks"
    assert f.finding_type == FindingType.SECRET
    assert f.severity == Severity.CRITICAL
    assert f.title == "AWS Access Key"
    assert f.file_path == ".env"
    assert f.start_line == 3
    assert f.end_line == 3
    assert f.rule_id == "aws-access-token"
    assert f.commit == "abc123"
    assert f.author == "jane"


def test_from_gitleaks_always_critical_regardless_of_rule():
    sample = [
        {"Description": "a", "File": "x", "RuleID": "r1", "StartLine": 1, "EndLine": 1},
        {"Description": "b", "File": "y", "RuleID": "r2", "StartLine": 2, "EndLine": 2},
    ]

    findings = from_gitleaks(sample)

    assert all(f.severity == Severity.CRITICAL for f in findings)

def test_from_gitleaks_missing_description_uses_default_title():
    sample = [{"File": "x", "RuleID": "r1", "StartLine": 1, "EndLine": 1}]
    assert from_gitleaks(sample)[0].title == "Secret detected"

def test_from_gitleaks_empty_list_returns_empty_list():
    assert from_gitleaks([]) == []

def test_from_gitleaks_none_input_returns_empty_list():
    assert from_gitleaks(None) == []

def test_from_gitleaks_description_includes_rule_id():
    sample = [{"Description": "x", "File": "y", "RuleID": "my-rule", "StartLine": 1, "EndLine": 1}]
    assert "my-rule" in from_gitleaks(sample)[0].description

def test_all_adapters_preserve_raw_payload():
    semgrep_raw = {
        "check_id": "a.b.c",
        "path": "x.py",
        "start": {"line": 1},
        "end": {"line": 1},
        "extra": {"severity": "INFO", "message": "", "metadata": {}},
    }
    trivy_raw = {"VulnerabilityID": "CVE-1", "Severity": "LOW", "Title": ""}
    gitleaks_raw = {"Description": "d", "File": "f", "RuleID": "r", "StartLine": 1, "EndLine": 1}

    assert from_semgrep({"results": [semgrep_raw]})[0].raw == semgrep_raw
    assert from_trivy({"Results": [{"Target": "t", "Vulnerabilities": [trivy_raw]}]})[0].raw == trivy_raw
    assert from_gitleaks([gitleaks_raw])[0].raw == gitleaks_raw






    


