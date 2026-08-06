"""
AST Engine: Multi-language AST parsing using tree-sitter.

Parses Python and JavaScript source code into Abstract Syntax Trees,
extracts function/method boundaries, and converts to a normalized
Intermediate Representation (IR) for language-agnostic analysis.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from loguru import logger


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    GO = "go"
    CPP = "cpp"
    RUST = "rust"


@dataclass
class CodeLocation:
    """Precise source location of a code element."""
    file: str
    line_start: int
    line_end: int
    col_start: int = 0
    col_end: int = 0

    def __str__(self) -> str:
        return f"{self.file}:{self.line_start}-{self.line_end}"


@dataclass
class CodeFunction:
    """Represents a parsed function/method from source code."""
    name: str
    language: Language
    source_code: str
    location: CodeLocation
    parameters: list[str] = field(default_factory=list)
    return_type: str | None = None
    is_method: bool = False
    class_name: str | None = None
    docstring: str | None = None
    complexity: int = 0  # cyclomatic complexity
    calls: list[str] = field(default_factory=list)  # function calls made inside
    imports: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Stable unique ID based on file + name + location."""
        key = f"{self.location.file}::{self.name}::{self.location.line_start}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def qualified_name(self) -> str:
        if self.class_name:
            return f"{self.class_name}.{self.name}"
        return self.name


@dataclass
class ParseResult:
    """Result of parsing a source file."""
    file_path: str
    language: Language
    functions: list[CodeFunction]
    imports: list[str]
    errors: list[str]
    raw_ast: Any = None  # tree-sitter node (optional, for advanced use)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0

    @property
    def function_count(self) -> int:
        return len(self.functions)


class ASTEngine:
    """
    Multi-language AST parsing engine using tree-sitter.

    Usage:
        engine = ASTEngine()
        result = engine.parse_file(Path("auth.py"))
        for func in result.functions:
            print(func.name, func.location)
    """

    def __init__(self) -> None:
        self._parsers: dict[Language, Any] = {}
        self._init_parsers()

    def _init_parsers(self) -> None:
        """Initialize tree-sitter parsers for each supported language."""
        try:
            import tree_sitter_python as tspython
            import tree_sitter_javascript as tsjs
            from tree_sitter import Language as TSLanguage, Parser

            self._parsers[Language.PYTHON] = Parser()
            self._parsers[Language.PYTHON].set_language(
                TSLanguage(tspython.language(), "python")
            )

            self._parsers[Language.JAVASCRIPT] = Parser()
            self._parsers[Language.JAVASCRIPT].set_language(
                TSLanguage(tsjs.language(), "javascript")
            )

            logger.info("AST parsers initialized for: Python, JavaScript")
        except ImportError as e:
            logger.warning(f"tree-sitter not installed: {e}. Run: pip install tree-sitter tree-sitter-python tree-sitter-javascript")

    def detect_language(self, file_path: Path) -> Language | None:
        """Detect programming language from file extension."""
        suffix_map = {
            ".py": Language.PYTHON,
            ".js": Language.JAVASCRIPT,
            ".mjs": Language.JAVASCRIPT,
            ".jsx": Language.JAVASCRIPT,
            ".ts": Language.JAVASCRIPT,  # simplified for now
            ".tsx": Language.JAVASCRIPT,
            ".java": Language.JAVA,
            ".go": Language.GO,
            ".cpp": Language.CPP,
            ".cc": Language.CPP,
            ".c": Language.CPP,
            ".rs": Language.RUST,
        }
        return suffix_map.get(file_path.suffix.lower())

    def parse_file(self, file_path: Path) -> ParseResult:
        """
        Parse a source file and extract all functions.

        Args:
            file_path: Path to source file

        Returns:
            ParseResult with all extracted functions and metadata
        """
        lang = self.detect_language(file_path)
        if lang is None:
            return ParseResult(
                file_path=str(file_path),
                language=Language.PYTHON,
                functions=[],
                imports=[],
                errors=[f"Unsupported file type: {file_path.suffix}"],
            )

        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
            return self.parse_source(source, lang, str(file_path))
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return ParseResult(
                file_path=str(file_path),
                language=lang,
                functions=[],
                imports=[],
                errors=[str(e)],
            )

    def parse_source(
        self, source: str, language: Language, file_path: str = "<string>"
    ) -> ParseResult:
        """
        Parse source code string and extract functions.

        Args:
            source: Source code as string
            language: Programming language
            file_path: Optional file path for location tracking

        Returns:
            ParseResult with extracted functions
        """
        parser = self._parsers.get(language)
        if parser is None:
            # Fallback: simple line-based extraction
            return self._fallback_parse(source, language, file_path)

        try:
            tree = parser.parse(bytes(source, "utf-8"))
            functions = self._extract_functions(tree.root_node, source, language, file_path)
            imports = self._extract_imports(tree.root_node, source, language)

            return ParseResult(
                file_path=file_path,
                language=language,
                functions=functions,
                imports=imports,
                errors=[],
                raw_ast=tree.root_node,
            )
        except Exception as e:
            logger.error(f"AST parse error for {file_path}: {e}")
            return self._fallback_parse(source, language, file_path)

    def _extract_functions(
        self, node: Any, source: str, language: Language, file_path: str
    ) -> list[CodeFunction]:
        """Walk the AST and collect all function definitions."""
        functions: list[CodeFunction] = []
        lines = source.splitlines()

        if language == Language.PYTHON:
            self._extract_python_functions(node, source, lines, file_path, functions)
        elif language == Language.JAVASCRIPT:
            self._extract_js_functions(node, source, lines, file_path, functions)

        return functions

    def _extract_python_functions(
        self, node: Any, source: str, lines: list[str],
        file_path: str, functions: list[CodeFunction],
        class_name: str | None = None,
    ) -> None:
        """Recursively extract Python function/method definitions."""
        function_node_types = {"function_definition", "async_function_definition"}
        class_node_types = {"class_definition"}

        for child in node.children:
            if child.type in class_node_types:
                # Get class name
                cname = self._get_node_text(child, source, "name")
                self._extract_python_functions(child, source, lines, file_path, functions, cname)
            elif child.type in function_node_types:
                func = self._build_python_function(child, source, lines, file_path, class_name)
                if func:
                    functions.append(func)
                # Check for nested functions
                self._extract_python_functions(child, source, lines, file_path, functions, class_name)
            else:
                self._extract_python_functions(child, source, lines, file_path, functions, class_name)

    def _build_python_function(
        self, node: Any, source: str, lines: list[str],
        file_path: str, class_name: str | None
    ) -> CodeFunction | None:
        """Build a CodeFunction from a Python function_definition node."""
        try:
            name = self._get_node_text(node, source, "name")
            if not name:
                return None

            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            func_source = "\n".join(lines[start_line - 1:end_line])

            # Extract parameters
            params = self._extract_python_params(node, source)

            # Compute cyclomatic complexity (count branches)
            complexity = self._compute_complexity(func_source)

            # Extract function calls
            calls = self._extract_calls(node, source)

            return CodeFunction(
                name=name,
                language=Language.PYTHON,
                source_code=func_source,
                location=CodeLocation(
                    file=file_path,
                    line_start=start_line,
                    line_end=end_line,
                    col_start=node.start_point[1],
                    col_end=node.end_point[1],
                ),
                parameters=params,
                is_method=class_name is not None,
                class_name=class_name,
                complexity=complexity,
                calls=calls,
            )
        except Exception as e:
            logger.debug(f"Failed to build function node: {e}")
            return None

    def _extract_js_functions(
        self, node: Any, source: str, lines: list[str],
        file_path: str, functions: list[CodeFunction],
        class_name: str | None = None,
    ) -> None:
        """Recursively extract JavaScript function definitions."""
        js_func_types = {
            "function_declaration", "function_expression",
            "arrow_function", "method_definition",
            "generator_function_declaration",
        }

        for child in node.children:
            if child.type == "class_declaration":
                cname = self._get_node_text(child, source, "name")
                self._extract_js_functions(child, source, lines, file_path, functions, cname)
            elif child.type in js_func_types:
                func = self._build_js_function(child, source, lines, file_path, class_name)
                if func:
                    functions.append(func)
                self._extract_js_functions(child, source, lines, file_path, functions, class_name)
            else:
                self._extract_js_functions(child, source, lines, file_path, functions, class_name)

    def _build_js_function(
        self, node: Any, source: str, lines: list[str],
        file_path: str, class_name: str | None,
    ) -> CodeFunction | None:
        """Build a CodeFunction from a JavaScript function node."""
        try:
            name = self._get_node_text(node, source, "name") or "<anonymous>"
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            func_source = "\n".join(lines[start_line - 1:end_line])
            complexity = self._compute_complexity(func_source)

            return CodeFunction(
                name=name,
                language=Language.JAVASCRIPT,
                source_code=func_source,
                location=CodeLocation(
                    file=file_path,
                    line_start=start_line,
                    line_end=end_line,
                ),
                is_method=class_name is not None,
                class_name=class_name,
                complexity=complexity,
                calls=self._extract_calls(node, source),
            )
        except Exception as e:
            logger.debug(f"Failed to build JS function: {e}")
            return None

    def _get_node_text(self, node: Any, source: str, field_name: str) -> str | None:
        """Get text content of a named child field."""
        try:
            child = node.child_by_field_name(field_name)
            if child:
                return source[child.start_byte:child.end_byte]
        except Exception:
            pass
        return None

    def _extract_python_params(self, node: Any, source: str) -> list[str]:
        """Extract parameter names from a Python function definition."""
        params = []
        try:
            params_node = node.child_by_field_name("parameters")
            if params_node:
                for child in params_node.children:
                    if child.type in {"identifier", "typed_parameter", "default_parameter"}:
                        # Get first identifier in each param
                        if child.type == "identifier":
                            params.append(source[child.start_byte:child.end_byte])
                        else:
                            for subchild in child.children:
                                if subchild.type == "identifier":
                                    params.append(source[subchild.start_byte:subchild.end_byte])
                                    break
        except Exception:
            pass
        return [p for p in params if p not in ("self", "cls")]

    def _extract_calls(self, node: Any, source: str) -> list[str]:
        """Collect all function call names within a node."""
        calls = []
        self._collect_calls(node, source, calls)
        return list(set(calls))

    def _collect_calls(self, node: Any, source: str, calls: list[str]) -> None:
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node:
                text = source[func_node.start_byte:func_node.end_byte]
                calls.append(text.split(".")[-1])  # strip object prefix
        for child in node.children:
            self._collect_calls(child, source, calls)

    def _extract_imports(self, node: Any, source: str, language: Language) -> list[str]:
        """Extract all import statements from the file."""
        imports = []
        import_types = {
            Language.PYTHON: {"import_statement", "import_from_statement"},
            Language.JAVASCRIPT: {"import_statement", "import_declaration"},
        }
        target_types = import_types.get(language, set())
        self._collect_node_texts(node, source, target_types, imports)
        return imports

    def _collect_node_texts(
        self, node: Any, source: str, types: set[str], results: list[str]
    ) -> None:
        if node.type in types:
            results.append(source[node.start_byte:node.end_byte].strip())
        for child in node.children:
            self._collect_node_texts(child, source, types, results)

    def _compute_complexity(self, source: str) -> int:
        """
        Approximate cyclomatic complexity by counting decision points.
        Full implementation would use CFG; this is a fast heuristic.
        """
        keywords = ["if ", "elif ", "else:", "for ", "while ", "except ", "and ", "or ", "case "]
        return 1 + sum(source.count(kw) for kw in keywords)

    def _fallback_parse(
        self, source: str, language: Language, file_path: str
    ) -> ParseResult:
        """
        Fallback parser using regex when tree-sitter is unavailable.
        Less accurate but always works.
        """
        import re
        functions = []
        lines = source.splitlines()

        if language == Language.PYTHON:
            pattern = re.compile(r"^(?:async\s+)?def\s+(\w+)\s*\(", re.MULTILINE)
        else:
            pattern = re.compile(r"(?:function\s+(\w+)|(\w+)\s*=\s*(?:async\s+)?(?:\(.*?\)|\w+)\s*=>)", re.MULTILINE)

        for match in pattern.finditer(source):
            name = match.group(1) or match.group(2)
            if not name:
                continue
            line_num = source[:match.start()].count("\n") + 1
            # Estimate function end: next def or end of file
            end_line = min(line_num + 30, len(lines))
            func_source = "\n".join(lines[line_num - 1:end_line])
            functions.append(CodeFunction(
                name=name,
                language=language,
                source_code=func_source,
                location=CodeLocation(file=file_path, line_start=line_num, line_end=end_line),
            ))

        return ParseResult(
            file_path=file_path,
            language=language,
            functions=functions,
            imports=[],
            errors=[],
        )
