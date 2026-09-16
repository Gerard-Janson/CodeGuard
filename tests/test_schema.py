from codeguard.findings.schema import (
    Finding,
    Severity,
    FindingType,
    SEVERITY_MAP,
)


def make_finding(**overrides):
    defaults = dict(
        tool="semgrep",
        finding_type=FindingType.SAST,
        severity=Severity.HIGH,
        title="some-rule",
        description="something is wrong",
        file_path="src/app.py",
        start_line=10,
    )
    defaults.update(overrides)
    return Finding(**defaults)

def test_severity_is_str_enum():
    """str subclassing matters so findings serialize to JSON without a custom encoder."""
    assert Severity.CRITICAL == "critical"
    assert isinstance(Severity.CRITICAL, str)


def test_finding_type_is_str_enum():
    assert FindingType.SAST == "sast"
    assert isinstance(FindingType.SAST, str)


def test_all_severity_levels_exist():
    assert {s.value for s in Severity} == {"critical", "high", "medium", "low", "info"}


def test_all_finding_types_exist():
    assert {t.value for t in FindingType} == {
        "sast",
        "dependency",
        "misconfig",
        "secret",
        "license",
    }

def test_SEVERITY_MAP_covers_semgrep_levels():
    assert SEVERITY_MAP["ERROR"] == Severity.HIGH
    assert SEVERITY_MAP["WARNING"] == Severity.MEDIUM
    assert SEVERITY_MAP["INFO"] == Severity.INFO


def test_SEVERITY_MAP_covers_trivy_levels():
    assert SEVERITY_MAP["CRITICAL"] == Severity.CRITICAL
    assert SEVERITY_MAP["HIGH"] == Severity.HIGH
    assert SEVERITY_MAP["MEDIUM"] == Severity.MEDIUM
    assert SEVERITY_MAP["LOW"] == Severity.LOW


def test_SEVERITY_MAP_handles_unknown():
    assert SEVERITY_MAP["UNKNOWN"] == Severity.INFO


def test_SEVERITY_MAP_keys_are_uppercase():
    """Adapters uppercase raw values before lookup, so keys must be uppercase."""
    assert all(key == key.upper() for key in SEVERITY_MAP)

def test_finding_requires_core_fields():
    f = make_finding()
    assert f.tool == "semgrep"
    assert f.finding_type == FindingType.SAST
    assert f.severity == Severity.HIGH
    assert f.title == "some-rule"
    assert f.file_path == "src/app.py"


def test_finding_optional_fields_default_to_none():
    f = make_finding()
    assert f.cve_id is None
    assert f.package_name is None
    assert f.installed_version is None
    assert f.fixed_version is None
    assert f.commit is None
    assert f.author is None


def test_finding_list_fields_default_to_empty_list():
    f = make_finding()
    assert f.cwe_ids == []
    assert f.references == []
    assert f.raw == {}


def test_finding_mutable_defaults_are_not_shared():
    """field(default_factory=list) must give each instance its own list."""
    a = make_finding()
    b = make_finding()
    a.cwe_ids.append("CWE-78")
    assert b.cwe_ids == []

def test_fingerprint_is_stable_for_identical_findings():
    a = make_finding(rule_id="r1")
    b = make_finding(rule_id="r1")
    assert a.fingerprint == b.fingerprint


def test_fingerprint_differs_when_file_differs():
    a = make_finding(file_path="src/a.py", rule_id="r1")
    b = make_finding(file_path="src/b.py", rule_id="r1")
    assert a.fingerprint != b.fingerprint


def test_fingerprint_differs_when_line_differs():
    a = make_finding(start_line=10, rule_id="r1")
    b = make_finding(start_line=20, rule_id="r1")
    assert a.fingerprint != b.fingerprint


def test_fingerprint_differs_when_rule_differs():
    a = make_finding(rule_id="r1")
    b = make_finding(rule_id="r2")
    assert a.fingerprint != b.fingerprint


def test_fingerprint_differs_across_tools():
    """Tool is part of the key, so two tools flagging the same line never collide."""
    a = make_finding(tool="semgrep", rule_id="r1")
    b = make_finding(tool="gitleaks", rule_id="r1")
    assert a.fingerprint != b.fingerprint


def test_fingerprint_is_sixteen_hex_chars():
    fp = make_finding().fingerprint
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_ignores_non_identity_fields():
    """Changing description/severity alone should not change identity."""
    a = make_finding(rule_id="r1", description="one", severity=Severity.LOW)
    b = make_finding(rule_id="r1", description="two", severity=Severity.CRITICAL)
    assert a.fingerprint == b.fingerprint


def test_severity_rank_orders_most_severe_first():
    ranks = [
        make_finding(severity=Severity.CRITICAL).severity_rank(),
        make_finding(severity=Severity.HIGH).severity_rank(),
        make_finding(severity=Severity.MEDIUM).severity_rank(),
        make_finding(severity=Severity.LOW).severity_rank(),
        make_finding(severity=Severity.INFO).severity_rank(),
    ]
    assert ranks == sorted(ranks)
    assert ranks == [0, 1, 2, 3, 4]


def test_severity_rank_critical_is_lowest_number():
    critical = make_finding(severity=Severity.CRITICAL).severity_rank()
    info = make_finding(severity=Severity.INFO).severity_rank()
    assert critical < info
