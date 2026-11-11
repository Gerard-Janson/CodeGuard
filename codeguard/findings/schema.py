import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Severity(str,Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingType(str, Enum):
    SAST = "sast"
    DEPENDENCY = "dependency"
    MISCONFIG = "misconfig"
    SECRET = "secret"
    LICENSE = "license"

SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO":Severity.INFO,
     "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "UNKNOWN":  Severity.INFO
}

@dataclass
class Finding:
    tool: str                    
    finding_type: FindingType
    severity: Severity
    title: str
    description: str
    file_path: str

    start_line: int | None = None
    end_line: int | None = None

    rule_id: str | None = None
    cve_id: str | None = None
    cwe_ids: list = field(default_factory=list)

    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None

    commit: str | None = None
    author: str | None = None

    references: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)  

    @property
    def fingerprint(self) -> str:
        key = f"{self.tool}:{self.file_path}:{self.rule_id}:{self.start_line}:{self.title}"
    
        return hashlib.sha256(key.encode()).hexdigest()[:16]


    def severity_rank(self) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order.get(self.severity, 5)

