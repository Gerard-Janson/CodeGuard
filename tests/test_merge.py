from codeguard.findings.merge import merge_findings
from codeguard.findings.schema import Finding, Severity, FindingType

def make_finding(**overrides):
    defaults = dict(
        tool="semgrep",
        finding_type=FindingType.SAST,
        severity=Severity.MEDIUM,
        title="some-rule",
        description="",
        file_path="src/app.py",
        start_line=1,
        rule_id="rule-1",
    )
    defaults.update(overrides)
    return Finding(**defaults)

def test_merge_combines_all_three_sources():
    semgrep = [make_finding(tool="semgrep", rule_id="s1")]
    trivy = [make_finding(tool="trivy", rule_id="t1", finding_type=FindingType.DEPENDENCY)]
    gitleaks = [make_finding(tool="gitleaks", rule_id="g1", finding_type=FindingType.SECRET)]

    result = merge_findings(semgrep, trivy, gitleaks)

    assert len(result) == 3
    assert {f.tool for f in result} == {"semgrep", "trivy", "gitleaks"}


def test_merge_all_empty_returns_empty_list():
    assert merge_findings([], [], []) == []


def test_merge_handles_some_empty_sources():
    """A scanner that failed contributes an empty list, not a crash."""
    trivy = [make_finding(tool="trivy", rule_id="t1")]
    result = merge_findings([], trivy, [])
    assert len(result) == 1
    assert result[0].tool == "trivy"


def test_merge_dedupes_identical_fingerprints():
    a = make_finding(rule_id="r1", start_line=5)
    b = make_finding(rule_id="r1", start_line=5)
    assert a.fingerprint == b.fingerprint

    result = merge_findings([a, b], [], [])
    assert len(result) == 1


def test_merge_keeps_distinct_findings_in_same_file():
    a = make_finding(rule_id="r1", start_line=5)
    b = make_finding(rule_id="r2", start_line=9)

    result = merge_findings([a, b], [], [])
    assert len(result) == 2


def test_merge_keeps_same_rule_on_different_lines():
    a = make_finding(rule_id="r1", start_line=5)
    b = make_finding(rule_id="r1", start_line=50)

    result = merge_findings([a, b], [], [])
    assert len(result) == 2


def test_merge_keeps_cross_tool_findings_on_same_line():
    """Tool is part of the fingerprint, so two tools flagging one line both survive."""
    semgrep = [make_finding(tool="semgrep", rule_id="secret", start_line=3)]
    gitleaks = [
        make_finding(
            tool="gitleaks",
            rule_id="secret",
            start_line=3,
            finding_type=FindingType.SECRET,
            severity=Severity.CRITICAL,
        )
    ]

    result = merge_findings(semgrep, [], gitleaks)
    assert len(result) == 2


def test_merge_dedupes_across_source_lists():
    """The same finding arriving from two lists is still one finding."""
    a = make_finding(rule_id="r1")
    b = make_finding(rule_id="r1")

    result = merge_findings([a], [b], [])
    assert len(result) == 1

def test_merge_sorts_by_severity_most_severe_first():
    low = make_finding(severity=Severity.LOW, rule_id="low")
    critical = make_finding(severity=Severity.CRITICAL, rule_id="crit")
    medium = make_finding(severity=Severity.MEDIUM, rule_id="med")

    result = merge_findings([low], [critical], [medium])

    assert [f.severity for f in result] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]


def test_merge_sorts_full_severity_ladder():
    findings = [
        make_finding(severity=Severity.INFO, rule_id="i"),
        make_finding(severity=Severity.HIGH, rule_id="h"),
        make_finding(severity=Severity.CRITICAL, rule_id="c"),
        make_finding(severity=Severity.LOW, rule_id="l"),
        make_finding(severity=Severity.MEDIUM, rule_id="m"),
    ]

    result = merge_findings(findings, [], [])

    assert [f.severity for f in result] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]

def test_merge_does_not_mutate_input_lists():
    semgrep = [make_finding(rule_id="r1")]
    original_length = len(semgrep)

    merge_findings(semgrep, [], [])

    assert len(semgrep) == original_length

def test_merge_returns_finding_objects():
    result = merge_findings([make_finding()], [], [])
    assert all(isinstance(f, Finding) for f in result)
