"""Authentication intelligence analyzer for JSXRay.

Extracts authentication mechanisms (headers, schemes, login/OAuth endpoints)
while filtering out informational/error strings.
"""

import re
from typing import List, Optional
from tree_sitter import Node
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.ast_utils import (
    extract_string_literal,
    get_node_line_col,
    get_node_snippet,
    get_node_text,
    get_object_properties,
    walk_tree,
)
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class AuthenticationAnalyzer(BaseAnalyzer):
    """Detects authentication mechanisms, headers, and endpoints without false positives on log messages."""

    @property
    def name(self) -> str:
        return "authentication"

    AUTH_HEADER_REGEX = re.compile(r"(?i)\b(?:Bearer|Token)\s+([a-zA-Z0-9_\-\.=]{16,})")
    AUTH_ROUTE_REGEX = re.compile(r"^/(?:api/)?(?:v[0-9]+/)?(auth|login|signin|sign-in|logout|oauth|sso|token|refresh|session|password/reset)(?:/|$|\?)", re.I)
    CSRF_HEADER_REGEX = re.compile(r"(?i)^(x-csrf-token|x-xsrf-token|csrf-token|xsrf-token)$")
    APIKEY_HEADER_REGEX = re.compile(r"(?i)^(x-api-key|x-access-token|x-auth-token|api-key)$")

    # Informational or error log strings to ignore
    IGNORED_AUTH_PHRASES = (
        "no token found", "token not found", "token is required", "missing token",
        "token expired", "invalid token", "failed to refresh token", "token has expired",
        "cannot find token", "token is missing", "error finding token",
    )

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.ast_root:
            return findings

        code_bytes = source.effective_code.encode("utf-8", errors="replace")
        code_lines = source.effective_code.splitlines()

        for node in walk_tree(source.ast_root):
            val: Optional[str] = None
            if node.type in ("string", "string_fragment"):
                val = extract_string_literal(node, code_bytes)
            elif node.type == "template_string":
                resolved, _, _ = reconstructor.resolve_expression(node)
                val = resolved

            if val:
                val_clean = val.strip()
                val_lower = val_clean.lower()

                # Filter out informational strings
                if any(phrase in val_lower for phrase in self.IGNORED_AUTH_PHRASES):
                    continue

                # 1. Bearer / Token Authorization in strings/templates
                auth_match = self.AUTH_HEADER_REGEX.search(val_clean)
                if auth_match and not any(k in val_lower for k in ("error", "warning", "logger", "console")):
                    line, col = get_node_line_col(node)
                    indicator = "Bearer Authorization Scheme" if "bearer" in val_lower else "Token Authorization Scheme"
                    findings.append(
                        Finding(
                            type=FindingType.AUTHENTICATION,
                            value=f"{indicator}: {auth_match.group(0)[:30]}...",
                            normalized_value=indicator,
                            confidence=Confidence.HIGH,
                            status=FindingStatus.DETECTED,
                            source_file=source.file_path,
                            source_url=source.url,
                            line=line,
                            column=col,
                            snippet=get_node_snippet(node, code_lines, code_bytes=code_bytes),
                            original_source=get_node_text(node, code_bytes).strip(),
                            reconstructed_source=val_clean,
                            discovery_method="AST analysis",
                            tags=["authentication", "auth-mechanism", "bearer-auth"],
                            extra_data={
                                "auth_type": "Bearer Scheme",
                                "mechanism": "Bearer Token Header",
                                "header_value": val_clean,
                            },
                        )
                    )

                # 2. Authentication Endpoints (/login, /oauth/token, /auth/refresh)
                if self.AUTH_ROUTE_REGEX.search(val_clean):
                    line, col = get_node_line_col(node)
                    findings.append(
                        Finding(
                            type=FindingType.AUTHENTICATION,
                            value=f"Auth Endpoint: {val_clean}",
                            normalized_value=val_clean,
                            confidence=Confidence.HIGH,
                            status=FindingStatus.DETECTED,
                            source_file=source.file_path,
                            source_url=source.url,
                            line=line,
                            column=col,
                            snippet=get_node_snippet(node, code_lines, code_bytes=code_bytes),
                            original_source=get_node_text(node, code_bytes).strip(),
                            reconstructed_source=val_clean,
                            discovery_method="AST analysis",
                            tags=["authentication", "auth-endpoint", "login-flow"],
                            extra_data={
                                "auth_type": "Endpoint",
                                "mechanism": "Authentication Endpoint",
                                "route": val_clean,
                            },
                        )
                    )

            # 3. Object properties for Headers (Authorization, X-CSRF-Token, X-Api-Key)
            if node.type == "object":
                props = get_object_properties(node, code_bytes)
                for key_name, val_node in props.items():
                    key_lower = key_name.lower()

                    if key_lower == "authorization":
                        val_str, _, _ = reconstructor.resolve_expression(val_node)
                        line, col = get_node_line_col(val_node)
                        findings.append(
                            Finding(
                                type=FindingType.AUTHENTICATION,
                                value=f"Authorization Header ({val_str or 'dynamic'})",
                                normalized_value="Authorization Header",
                                confidence=Confidence.HIGH,
                                status=FindingStatus.DETECTED,
                                source_file=source.file_path,
                                source_url=source.url,
                                line=line,
                                column=col,
                                snippet=get_node_snippet(node, code_lines, code_bytes=code_bytes),
                                original_source=get_node_text(node, code_bytes).strip(),
                                reconstructed_source=val_str or key_name,
                                discovery_method="AST analysis",
                                tags=["authentication", "authorization-header", "auth-mechanism"],
                                extra_data={
                                    "auth_type": "Header",
                                    "mechanism": "Authorization Header",
                                    "header_name": key_name,
                                },
                            )
                        )

                    elif self.CSRF_HEADER_REGEX.match(key_lower):
                        line, col = get_node_line_col(val_node)
                        findings.append(
                            Finding(
                                type=FindingType.AUTHENTICATION,
                                value=f"CSRF Protection Header: {key_name}",
                                normalized_value=f"CSRF Header: {key_name}",
                                confidence=Confidence.HIGH,
                                status=FindingStatus.DETECTED,
                                source_file=source.file_path,
                                source_url=source.url,
                                line=line,
                                column=col,
                                snippet=get_node_snippet(node, code_lines, code_bytes=code_bytes),
                                original_source=get_node_text(node, code_bytes).strip(),
                                reconstructed_source=key_name,
                                discovery_method="AST analysis",
                                tags=["authentication", "csrf-token", "auth-mechanism"],
                                extra_data={
                                    "auth_type": "CSRF",
                                    "mechanism": "CSRF Token Header",
                                    "header_name": key_name,
                                },
                            )
                        )

                    elif self.APIKEY_HEADER_REGEX.match(key_lower):
                        line, col = get_node_line_col(val_node)
                        findings.append(
                            Finding(
                                type=FindingType.AUTHENTICATION,
                                value=f"API Key Header: {key_name}",
                                normalized_value=f"API Key Header: {key_name}",
                                confidence=Confidence.HIGH,
                                status=FindingStatus.DETECTED,
                                source_file=source.file_path,
                                source_url=source.url,
                                line=line,
                                column=col,
                                snippet=get_node_snippet(node, code_lines, code_bytes=code_bytes),
                                original_source=get_node_text(node, code_bytes).strip(),
                                reconstructed_source=key_name,
                                discovery_method="AST analysis",
                                tags=["authentication", "api-key-header", "auth-mechanism"],
                                extra_data={
                                    "auth_type": "API-Key",
                                    "mechanism": "API Key Header",
                                    "header_name": key_name,
                                },
                            )
                        )

        return findings
