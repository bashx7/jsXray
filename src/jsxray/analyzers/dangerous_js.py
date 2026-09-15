"""Dangerous JavaScript sink and DOM manipulation analyzer for JSXRay.

Identifies DOM injection, dynamic execution, and navigation sinks while distinguishing
static constant navigations from untrusted data flows.
"""

from typing import List, Optional
from tree_sitter import Node
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.ast_utils import (
    extract_string_literal,
    get_node_line_col,
    get_node_snippet,
    get_node_text,
    walk_tree,
)
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class DangerousJsAnalyzer(BaseAnalyzer):
    """Analyzes DOM sinks and dynamic execution vectors with exploitability context."""

    @property
    def name(self) -> str:
        return "dangerous_js"

    DANGEROUS_CALL_SINKS = {
        "eval": ("eval", "Dynamic Code Evaluation Sink"),
        "Function": ("Function", "Dynamic Function Constructor Sink"),
        "document.write": ("document.write", "DOM Document Write Sink"),
        "document.writeln": ("document.writeln", "DOM Document Write Sink"),
        "window.postMessage": ("postMessage", "Cross-Origin Message Sink"),
        "postMessage": ("postMessage", "Cross-Origin Message Sink"),
    }

    DOM_INJECTION_PROPERTIES = {
        "innerHTML": "HTML Injection Sink (innerHTML)",
        "outerHTML": "HTML Injection Sink (outerHTML)",
        "srcdoc": "Iframe Source Document Sink (srcdoc)",
    }

    NAVIGATION_PROPERTIES = {
        "location.href": "Client-Side Navigation Sink (location.href)",
        "location.assign": "Client-Side Navigation Sink (location.assign)",
        "location.replace": "Client-Side Navigation Sink (location.replace)",
        "window.location": "Client-Side Navigation Sink (window.location)",
    }

    UNTRUSTED_INPUT_INDICATORS = (
        "location.search", "location.hash", "location.href", "window.name",
        "document.referrer", "document.cookie", "URLSearchParams",
        "params.", "query.", "route.params", "$route", "searchParams",
        "event.data", "e.data",
    )

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.ast_root:
            return findings

        code_bytes = source.effective_code.encode("utf-8", errors="replace")
        code_lines = source.effective_code.splitlines()

        for node in walk_tree(source.ast_root):
            # 1. Call expressions: eval(), Function(), document.write(), setTimeout(string)
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                args_node = node.child_by_field_name("arguments")
                if func_node:
                    func_text = get_node_text(func_node, code_bytes).strip()

                    # Direct call sinks
                    sink_entry = self.DANGEROUS_CALL_SINKS.get(func_text)
                    if sink_entry:
                        sink_name, sink_desc = sink_entry
                        line, col = get_node_line_col(node)
                        snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)

                        # Determine if argument is dynamic or constant
                        is_dynamic = True
                        if args_node:
                            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                            if args and args[0].type in ("string", "string_fragment"):
                                is_dynamic = False

                        exploitability = "Requires attacker-controlled input" if is_dynamic else "Static constant invocation"
                        status = FindingStatus.DETECTED if is_dynamic else FindingStatus.POTENTIAL

                        findings.append(
                            Finding(
                                type=FindingType.DANGEROUS_JS,
                                value=f"Dangerous Sink: {sink_name}",
                                normalized_value=sink_name,
                                confidence=Confidence.HIGH if is_dynamic else Confidence.MEDIUM,
                                status=status,
                                source_file=source.file_path,
                                source_url=source.url,
                                line=line,
                                column=col,
                                snippet=snippet,
                                original_source=get_node_text(node, code_bytes).strip(),
                                reconstructed_source=sink_name,
                                discovery_method="AST analysis",
                                tags=["dangerous-js", "sink", sink_name.lower().replace(".", "-")],
                                extra_data={
                                    "sink": sink_name,
                                    "description": sink_desc,
                                    "exploitability": exploitability,
                                    "is_dynamic": is_dynamic,
                                },
                            )
                        )

                    # setTimeout / setInterval with string argument
                    elif func_text in ("setTimeout", "setInterval", "window.setTimeout", "window.setInterval"):
                        if args_node:
                            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                            if args and args[0].type in ("string", "template_string", "binary_expression"):
                                line, col = get_node_line_col(node)
                                snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)
                                findings.append(
                                    Finding(
                                        type=FindingType.DANGEROUS_JS,
                                        value=f"Dangerous Sink: {func_text}(string)",
                                        normalized_value=func_text,
                                        confidence=Confidence.MEDIUM,
                                        status=FindingStatus.DETECTED,
                                        source_file=source.file_path,
                                        source_url=source.url,
                                        line=line,
                                        column=col,
                                        snippet=snippet,
                                        original_source=get_node_text(node, code_bytes).strip(),
                                        reconstructed_source=func_text,
                                        discovery_method="AST analysis",
                                        tags=["dangerous-js", "dynamic-eval", "timer-sink"],
                                        extra_data={
                                            "sink": func_text,
                                            "description": "Timer string evaluation (implicit eval)",
                                            "exploitability": "Requires attacker-controlled string input",
                                        },
                                    )
                                )

            # 2. Assignment expressions: innerHTML, location.href, srcdoc
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left:
                    left_text = get_node_text(left, code_bytes).strip()
                    right_text = get_node_text(right, code_bytes).strip() if right else ""

                    # 2A. DOM HTML injection (innerHTML, outerHTML, srcdoc)
                    for prop_name, prop_desc in self.DOM_INJECTION_PROPERTIES.items():
                        if left_text.endswith(f".{prop_name}") or left_text == prop_name:
                            line, col = get_node_line_col(node)
                            snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)

                            is_constant = (right and right.type in ("string", "string_fragment"))
                            exploitability = "Static HTML template assignment" if is_constant else "Requires attacker-controlled input"

                            findings.append(
                                Finding(
                                    type=FindingType.DANGEROUS_JS,
                                    value=f"Dangerous Sink: {prop_name}",
                                    normalized_value=prop_name,
                                    confidence=Confidence.HIGH if not is_constant else Confidence.MEDIUM,
                                    status=FindingStatus.DETECTED if not is_constant else FindingStatus.POTENTIAL,
                                    source_file=source.file_path,
                                    source_url=source.url,
                                    line=line,
                                    column=col,
                                    snippet=snippet,
                                    original_source=get_node_text(node, code_bytes).strip(),
                                    reconstructed_source=left_text,
                                    discovery_method="AST analysis",
                                    tags=["dangerous-js", "dom-injection", prop_name.lower()],
                                    extra_data={
                                        "sink": prop_name,
                                        "target": left_text,
                                        "description": prop_desc,
                                        "exploitability": exploitability,
                                        "is_constant": is_constant,
                                    },
                                )
                            )
                            break

                    # 2B. Location manipulation (location.href, location.assign)
                    for loc_prop, loc_desc in self.NAVIGATION_PROPERTIES.items():
                        if loc_prop in left_text:
                            line, col = get_node_line_col(node)
                            snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)

                            # Check if assignment is a constant literal like "/login" or dynamic
                            is_constant = False
                            if right and right.type in ("string", "string_fragment"):
                                lit_val = extract_string_literal(right, code_bytes) or ""
                                if lit_val.startswith("/") or not lit_val.startswith("http"):
                                    is_constant = True

                            has_untrusted_input = any(inp in right_text for inp in self.UNTRUSTED_INPUT_INDICATORS)
                            exploitability = "Dynamic input flows into navigation sink" if has_untrusted_input else ("Static client navigation" if is_constant else "Requires attacker-controlled input")

                            findings.append(
                                Finding(
                                    type=FindingType.DANGEROUS_JS,
                                    value=f"Dangerous Sink: {loc_prop}",
                                    normalized_value=loc_prop,
                                    confidence=Confidence.HIGH if has_untrusted_input else Confidence.MEDIUM,
                                    status=FindingStatus.DETECTED if has_untrusted_input else FindingStatus.POTENTIAL,
                                    source_file=source.file_path,
                                    source_url=source.url,
                                    line=line,
                                    column=col,
                                    snippet=snippet,
                                    original_source=get_node_text(node, code_bytes).strip(),
                                    reconstructed_source=left_text,
                                    discovery_method="AST analysis",
                                    tags=["dangerous-js", "client-navigation", "location-sink"],
                                    extra_data={
                                        "sink": loc_prop,
                                        "target": left_text,
                                        "description": loc_desc,
                                        "exploitability": exploitability,
                                        "is_constant": is_constant,
                                    },
                                )
                            )
                            break

        return findings
