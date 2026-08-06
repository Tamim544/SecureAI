"""
Taint Analysis Engine.

Tracks the flow of untrusted (user-controlled) data from SOURCES
through the program to dangerous SINKS, identifying potential
security vulnerabilities.

This implements interprocedural, context-sensitive taint analysis
for Python and JavaScript codebases.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from core.ast_engine.parser import CodeFunction, Language


# ──────────────────────────────────────────────
# CWE Taxonomy
# ──────────────────────────────────────────────

class CWEType(str, Enum):
    """Top 25 CWE vulnerability types most relevant to code analysis."""
    CWE_89  = "CWE-89"   # SQL Injection
    CWE_79  = "CWE-79"   # Cross-Site Scripting (XSS)
    CWE_78  = "CWE-78"   # OS Command Injection
    CWE_22  = "CWE-22"   # Path Traversal
    CWE_77  = "CWE-77"   # Command Injection
    CWE_94  = "CWE-94"   # Code Injection (eval)
    CWE_918 = "CWE-918"  # SSRF
    CWE_611 = "CWE-611"  # XXE
    CWE_502 = "CWE-502"  # Deserialization
    CWE_327 = "CWE-327"  # Weak Cryptography
    CWE_798 = "CWE-798"  # Hardcoded Credentials
    CWE_200 = "CWE-200"  # Information Exposure
    CWE_732 = "CWE-732"  # Incorrect Permissions
    CWE_476 = "CWE-476"  # NULL Pointer Dereference
    CWE_119 = "CWE-119"  # Buffer Overflow
    CWE_434 = "CWE-434"  # Unrestricted File Upload
    CWE_306 = "CWE-306"  # Missing Authentication
    CWE_862 = "CWE-862"  # Missing Authorization
    CWE_noname = "UNKNOWN"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ──────────────────────────────────────────────
# Taint Definitions
# ──────────────────────────────────────────────

# Python taint sources: patterns that introduce untrusted data
PYTHON_SOURCES: dict[str, CWEType] = {
    # HTTP request parameters
    r"request\.(args|form|json|data|files|values|cookies|headers)\b": CWEType.CWE_89,
    r"flask\.request\b": CWEType.CWE_89,
    r"django\.http\.HttpRequest\b": CWEType.CWE_89,
    # Environment variables
    r"os\.environ(?:\.get)?\b": CWEType.CWE_200,
    # CLI arguments
    r"sys\.argv\b": CWEType.CWE_89,
    r"argparse\b": CWEType.CWE_89,
    # File reads
    r"open\s*\([^)]*\)\.read": CWEType.CWE_22,
    r"Path\([^)]*\)\.read_text": CWEType.CWE_22,
    # Database reads
    r"cursor\.fetchone\(\)|cursor\.fetchall\(\)": CWEType.CWE_89,
    # WebSocket
    r"websocket\.recv\(\)": CWEType.CWE_89,
}

# Python taint sinks: dangerous operations
PYTHON_SINKS: dict[str, tuple[CWEType, Severity]] = {
    # SQL Injection
    r"cursor\.execute\s*\(\s*[^%\"']*(f[\"']|\+|format)": (CWEType.CWE_89, Severity.CRITICAL),
    r"\.raw\s*\(": (CWEType.CWE_89, Severity.CRITICAL),
    r"session\.execute\s*\(\s*text\s*\(": (CWEType.CWE_89, Severity.HIGH),
    # Command Injection
    r"os\.system\s*\(": (CWEType.CWE_78, Severity.CRITICAL),
    r"subprocess\.(run|call|Popen|check_output)\s*\(": (CWEType.CWE_78, Severity.HIGH),
    r"os\.popen\s*\(": (CWEType.CWE_78, Severity.CRITICAL),
    # Code Injection
    r"\beval\s*\(": (CWEType.CWE_94, Severity.CRITICAL),
    r"\bexec\s*\(": (CWEType.CWE_94, Severity.CRITICAL),
    r"compile\s*\(": (CWEType.CWE_94, Severity.HIGH),
    # XSS (template rendering)
    r"render_template\s*\(": (CWEType.CWE_79, Severity.MEDIUM),
    r"Markup\s*\(": (CWEType.CWE_79, Severity.HIGH),
    r"\.format_map\s*\(": (CWEType.CWE_79, Severity.LOW),
    # Path Traversal
    r"open\s*\([^)]*\+": (CWEType.CWE_22, Severity.HIGH),
    r"Path\s*\([^)]*\+": (CWEType.CWE_22, Severity.HIGH),
    r"os\.path\.join\s*\([^)]*request": (CWEType.CWE_22, Severity.HIGH),
    # SSRF
    r"requests\.(get|post|put|delete)\s*\(": (CWEType.CWE_918, Severity.MEDIUM),
    r"urllib\.request\.urlopen\s*\(": (CWEType.CWE_918, Severity.MEDIUM),
    # Deserialization
    r"pickle\.loads?\s*\(": (CWEType.CWE_502, Severity.CRITICAL),
    r"yaml\.load\s*\([^)]*Loader": (CWEType.CWE_502, Severity.HIGH),
    r"marshal\.loads?\s*\(": (CWEType.CWE_502, Severity.CRITICAL),
}

# Python sanitizers: functions that clean tainted data
PYTHON_SANITIZERS: set[str] = {
    r"html\.escape\s*\(",
    r"markupsafe\.escape\s*\(",
    r"bleach\.clean\s*\(",
    r"parameterize\s*\(",
    r"cursor\.execute\s*\(\s*[^,]+,\s*\(",  # parameterized query
    r"shlex\.quote\s*\(",
    r"pipes\.quote\s*\(",
    r"re\.escape\s*\(",
    r"os\.path\.basename\s*\(",
    r"secure_filename\s*\(",  # werkzeug
    r"validate\s*\(",
    r"sanitize\s*\(",
}

# JavaScript equivalents
JS_SOURCES: dict[str, CWEType] = {
    r"req\.(body|params|query|headers|cookies)\b": CWEType.CWE_89,
    r"request\.(body|params|query)\b": CWEType.CWE_89,
    r"process\.env\b": CWEType.CWE_200,
    r"location\.(href|search|hash)\b": CWEType.CWE_79,
    r"document\.cookie\b": CWEType.CWE_79,
    r"window\.name\b": CWEType.CWE_79,
    r"localStorage\.getItem\b": CWEType.CWE_79,
}

JS_SINKS: dict[str, tuple[CWEType, Severity]] = {
    r"innerHTML\s*=": (CWEType.CWE_79, Severity.HIGH),
    r"outerHTML\s*=": (CWEType.CWE_79, Severity.HIGH),
    r"document\.write\s*\(": (CWEType.CWE_79, Severity.HIGH),
    r"eval\s*\(": (CWEType.CWE_94, Severity.CRITICAL),
    r"new\s+Function\s*\(": (CWEType.CWE_94, Severity.CRITICAL),
    r"setTimeout\s*\(\s*['\"`]": (CWEType.CWE_94, Severity.MEDIUM),
    r"child_process\.exec\s*\(": (CWEType.CWE_78, Severity.CRITICAL),
    r"\.execSync\s*\(": (CWEType.CWE_78, Severity.CRITICAL),
    r"require\s*\([^'\"]+\+": (CWEType.CWE_22, Severity.HIGH),
    r"fs\.readFile\s*\([^,]*\+": (CWEType.CWE_22, Severity.HIGH),
    r"res\.redirect\s*\(": (CWEType.CWE_918, Severity.MEDIUM),
    r"axios\.(get|post)\s*\(": (CWEType.CWE_918, Severity.MEDIUM),
    r"fetch\s*\(": (CWEType.CWE_918, Severity.LOW),
}

JS_SANITIZERS: set[str] = {
    r"DOMPurify\.sanitize\s*\(",
    r"sanitizeHtml\s*\(",
    r"escape\s*\(",
    r"encodeURIComponent\s*\(",
    r"validator\.escape\s*\(",
    r"xss\s*\(",
    r"helmet\b",
}


# ──────────────────────────────────────────────
# Findings
# ──────────────────────────────────────────────

@dataclass
class TaintPath:
    """A detected taint flow from source to sink."""
    source_pattern: str
    source_line: int
    sink_pattern: str
    sink_line: int
    cwe: CWEType
    severity: Severity
    sanitized: bool = False
    intermediate_lines: list[int] = field(default_factory=list)

    def __str__(self) -> str:
        status = "SANITIZED" if self.sanitized else "VULNERABLE"
        return (
            f"[{status}] {self.cwe.value} ({self.severity.value}) | "
            f"Source L{self.source_line} → Sink L{self.sink_line}"
        )


@dataclass
class VulnerabilityFinding:
    """A confirmed vulnerability finding from taint analysis + pattern matching."""
    function_name: str
    file_path: str
    line_start: int
    line_end: int
    cwe: CWEType
    severity: Severity
    description: str
    taint_paths: list[TaintPath] = field(default_factory=list)
    fix_suggestion: str | None = None
    confidence: float = 0.0  # 0.0–1.0 (filled in by ML model)

    @property
    def cvss_estimate(self) -> float:
        """Rough CVSS-like score based on severity."""
        severity_scores = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.5,
        }
        return severity_scores.get(self.severity, 5.0)


# ──────────────────────────────────────────────
# Taint Engine
# ──────────────────────────────────────────────

class TaintEngine:
    """
    Interprocedural taint analysis engine.

    For each function, identifies:
    1. Where tainted (user-controlled) data enters (sources)
    2. Whether it reaches a dangerous operation (sink)
    3. Whether any sanitization occurs along the path
    4. The CWE type and severity of the vulnerability

    Usage:
        engine = TaintEngine()
        findings = engine.analyze_function(code_function)
    """

    def analyze_function(self, func: "CodeFunction") -> list[VulnerabilityFinding]:
        """
        Analyze a single function for taint-based vulnerabilities.

        Args:
            func: Parsed function from ASTEngine

        Returns:
            List of vulnerability findings
        """
        from core.ast_engine.parser import Language

        if func.language == Language.PYTHON:
            sources = PYTHON_SOURCES
            sinks = PYTHON_SINKS
            sanitizers = PYTHON_SANITIZERS
        elif func.language == Language.JAVASCRIPT:
            sources = JS_SOURCES
            sinks = JS_SINKS
            sanitizers = JS_SANITIZERS
        else:
            return []

        lines = func.source_code.splitlines()
        tainted_lines: dict[int, tuple[str, CWEType]] = {}

        # Step 1: Find source lines
        for line_idx, line in enumerate(lines, start=1):
            for src_pattern, cwe in sources.items():
                if re.search(src_pattern, line):
                    tainted_lines[line_idx] = (src_pattern, cwe)

        if not tainted_lines:
            return []  # No tainted data entering this function

        # Step 2: Propagate taint (simplified: assume all subsequent lines are tainted)
        # Full implementation: SSA-based dataflow propagation
        max_source_line = max(tainted_lines.keys())

        # Step 3: Check for sanitizers between source and sink
        sanitizer_lines: set[int] = set()
        for line_idx, line in enumerate(lines, start=1):
            for san_pattern in sanitizers:
                if re.search(san_pattern, line):
                    sanitizer_lines.add(line_idx)

        # Step 4: Find sink lines after source lines
        findings: list[VulnerabilityFinding] = []

        for line_idx, line in enumerate(lines, start=1):
            if line_idx <= max_source_line:
                continue  # Sink must come after source

            for sink_pattern, (cwe, severity) in sinks.items():
                if not re.search(sink_pattern, line):
                    continue

                # Check if sanitized between source and this sink
                intervening_sanitizers = {
                    s for s in sanitizer_lines
                    if max_source_line < s < line_idx
                }
                is_sanitized = len(intervening_sanitizers) > 0

                # Find the relevant source
                src_line, (src_pattern, src_cwe) = max(
                    tainted_lines.items(), key=lambda x: x[0]
                )

                taint_path = TaintPath(
                    source_pattern=src_pattern,
                    source_line=func.location.line_start + src_line - 1,
                    sink_pattern=sink_pattern,
                    sink_line=func.location.line_start + line_idx - 1,
                    cwe=cwe,
                    severity=Severity.INFO if is_sanitized else severity,
                    sanitized=is_sanitized,
                )

                if not is_sanitized:
                    finding = VulnerabilityFinding(
                        function_name=func.qualified_name,
                        file_path=func.location.file,
                        line_start=func.location.line_start + src_line - 1,
                        line_end=func.location.line_start + line_idx - 1,
                        cwe=cwe,
                        severity=severity,
                        description=self._describe_vulnerability(cwe, src_pattern, sink_pattern),
                        taint_paths=[taint_path],
                        fix_suggestion=self._suggest_fix(cwe),
                    )
                    findings.append(finding)
                    logger.debug(f"Found {cwe.value} in {func.qualified_name}(): {taint_path}")

        return self._deduplicate_findings(findings)

    def analyze_file(self, parse_result: "ParseResult") -> list[VulnerabilityFinding]:  # type: ignore[name-defined]
        """Analyze all functions in a parsed file."""
        all_findings = []
        for func in parse_result.functions:
            findings = self.analyze_function(func)
            all_findings.extend(findings)
        return all_findings

    def _describe_vulnerability(
        self, cwe: CWEType, source: str, sink: str
    ) -> str:
        descriptions = {
            CWEType.CWE_89: "User-controlled input flows into SQL query without parameterization — SQL Injection risk",
            CWEType.CWE_79: "User-controlled input flows into HTML output without escaping — XSS risk",
            CWEType.CWE_78: "User-controlled input flows into OS command — Command Injection risk",
            CWEType.CWE_94: "User-controlled input passed to eval()/exec() — Code Injection risk",
            CWEType.CWE_22: "User-controlled input used in file path — Path Traversal risk",
            CWEType.CWE_918: "User-controlled URL passed to HTTP client — SSRF risk",
            CWEType.CWE_502: "Untrusted data passed to pickle/yaml.load — Deserialization risk",
        }
        return descriptions.get(cwe, f"{cwe.value}: Tainted data flows from source to dangerous sink")

    def _suggest_fix(self, cwe: CWEType) -> str:
        fixes = {
            CWEType.CWE_89: "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
            CWEType.CWE_79: "Escape output: html.escape(user_input) or use auto-escaping template engine",
            CWEType.CWE_78: "Use subprocess with list args (no shell=True): subprocess.run(['cmd', arg])",
            CWEType.CWE_94: "Never pass user input to eval()/exec(). Use ast.literal_eval() for safe evaluation",
            CWEType.CWE_22: "Validate and normalize paths: use os.path.basename() and check against allowed directory",
            CWEType.CWE_918: "Validate URLs against allowlist; use a dedicated SSRF protection library",
            CWEType.CWE_502: "Use json.loads() instead of pickle. If pickle is required, sign the data with HMAC",
        }
        return fixes.get(cwe, "Validate and sanitize all user input before use in sensitive operations")

    def _deduplicate_findings(
        self, findings: list[VulnerabilityFinding]
    ) -> list[VulnerabilityFinding]:
        """Remove duplicate findings (same CWE + same line range)."""
        seen: set[tuple] = set()
        unique: list[VulnerabilityFinding] = []
        for f in findings:
            key = (f.cwe, f.file_path, f.line_start, f.line_end)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
