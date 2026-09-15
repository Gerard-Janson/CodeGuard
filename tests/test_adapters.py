from codeguard.findings.adapters import from_semgrep,from_gitleaks,from_trivy
from codeguard.findings.schema import FindingType,Severity

def test_from_semgrep_normal_results():
    sample = {
        "results": [
            {
                "check_id": "python.lang.security.some-rule",
                "path": "src/app.py",
                "start": {"line": 10},
                "end": {"line": 10},
                "extra": {
                    "message": "Some vulnerability message",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-78"],
                        "references": ["https://example.com"]
                    }
                }
            }
        ]
    }

    findings = from_semgrep(sample)

    assert len(findings) == 1
    assert findings[0].tool == "semgrep"
    assert findings[0].finding_type == FindingType.SAST
    assert findings[0].severity == Severity.HIGH      
    assert findings[0].title == "some-rule"            
    assert findings[0].file_path == "src/app.py"
    assert findings[0].start_line == 10
    assert findings[0].cwe_ids == ["CWE-78"]

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


    


