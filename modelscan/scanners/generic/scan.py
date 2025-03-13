import logging
import json
import re
from typing import Optional
import os
from modelscan.settings import SupportedModelFormats
from modelscan.scanners.scan import ScanBase, ScanResults
from modelscan.model import Model
from modelscan.issues import (
    Issue,
    IssueCode,
    IssueSeverity,
    OperatorIssueDetails,
    FormatIssueDetails,
    JSONParsingIssueDetails,
    SuspiciousPatternIssueDetails,
    InvalidEncodingIssueDetails,
)

logger = logging.getLogger("modelscan")

SUSPICIOUS_PATTERNS = [
    r'import\s+os',
    r'import\s+sys',
    r'eval\s*\(',
    r'exec\s*\(',
    r'subprocess\.',
    r'os\.system',
    r'rm\s+-rf'
]

class GenericUnsafeScan(ScanBase):
    def scan(self, model: Model) -> Optional[ScanResults]:
        source = model.get_source() 
        stream = model.get_stream()  

        exclude_ext = [".pb", ".h5", ".keras", ".npy", ".bin", ".pt", ".pth", ".ckpt",
        ".pkl", ".pickle", ".joblib", ".dill", ".dat", ".data", ".safetensors"
        ]

        
        if SupportedModelFormats.GENERIC.value not in [fmt.value for fmt in model.get_context("formats")] and not os.access(source, os.R_OK):
            return None

        
        if source.suffix in exclude_ext:
            return None

        results = []
        issues = []

        content = ""
        try:
            content = stream.read().decode("utf-8", errors="ignore")
        except Exception as e:
            severity = IssueSeverity.LOW
            issue = Issue(
                code=IssueCode.INVALID_ENCODING,
                severity=severity,
                details=InvalidEncodingIssueDetails(
                    source=model.get_source(),
                    error=str(e),
                    severity=severity,
                    scanner="generic"
                )
            )
            issues.append(issue)


        if source.suffix == ".json":
            try:
                json.loads(content)
            except Exception as e:
                severity = IssueSeverity.LOW
                issue = Issue(
                    code=IssueCode.JSON_PARSING_FAILED,
                    severity=severity,
                    details=JSONParsingIssueDetails(
                        error=str(e),
                        source=model.get_source(),
                        severity=severity,
                        scanner="generic"
                    )
                )
                issues.append(issue)

        if source.suffix != ".py":
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    severity = IssueSeverity.LOW
                    issue = Issue(
                        code=IssueCode.SUSPICIOUS_PATTERN,
                        severity=severity,
                        details=SuspiciousPatternIssueDetails(
                            pattern=pattern,
                            source=model.get_source(),
                            severity=severity,
                            scanner="generic"
                        )
                    )
                    issues.append(issue)
                    break

        result = ScanResults(issues, [], [])
        return self.label_results(result)

    @staticmethod
    def name() -> str:
        return "generic"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.GenericUnsafeScan"
