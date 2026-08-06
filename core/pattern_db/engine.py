"""
Static Pattern Rule Engine.

Loads YAML-based vulnerability signatures and matches them against source code.
Acts as a lightweight, ML-augmented alternative to Semgrep.
"""
from __future__ import annotations

import re
import yaml
from pathlib import Path
from loguru import logger
from typing import Any

from core.taint_engine.analyzer import VulnerabilityFinding, CWEType, Severity


class PatternEngine:
    def __init__(self, rules_dir: str = "core/pattern_db/rules"):
        self.rules_dir = Path(rules_dir)
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        rules = []
        if not self.rules_dir.exists():
            return rules
            
        for filepath in self.rules_dir.glob("*.yaml"):
            try:
                with open(filepath, "r") as f:
                    docs = yaml.safe_load_all(f)
                    for doc in docs:
                        if doc:
                            rules.append(doc)
            except Exception as e:
                logger.error(f"Failed to load rule file {filepath}: {e}")
                
        logger.info(f"Loaded {len(rules)} static pattern rules")
        return rules

    def scan(self, code: str, language: str, file_path: str) -> list[VulnerabilityFinding]:
        """Scan code against loaded regex/pattern rules."""
        findings = []
        lines = code.splitlines()
        
        for rule in self.rules:
            if rule.get("language") != language:
                continue
                
            for pattern_def in rule.get("pattern", []):
                if pattern_def.get("type") == "regex":
                    regex = pattern_def.get("match")
                    if not regex:
                        continue
                    
                    try:
                        compiled = re.compile(regex)
                        for line_idx, line in enumerate(lines, start=1):
                            if compiled.search(line):
                                try:
                                    cwe = CWEType(rule.get("cwe", "UNKNOWN"))
                                except ValueError:
                                    cwe = CWEType.CWE_noname
                                    
                                try:
                                    severity = Severity(rule.get("severity", "MEDIUM"))
                                except ValueError:
                                    severity = Severity.MEDIUM

                                finding = VulnerabilityFinding(
                                    function_name="<pattern_match>",
                                    file_path=file_path,
                                    line_start=line_idx,
                                    line_end=line_idx,
                                    cwe=cwe,
                                    severity=severity,
                                    description=rule.get("description", ""),
                                    fix_suggestion=rule.get("fix_template", ""),
                                )
                                findings.append(finding)
                    except re.error as e:
                        logger.debug(f"Invalid regex in rule {rule.get('id')}: {e}")
                        
        return findings
