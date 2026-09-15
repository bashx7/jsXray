"""Hardcoded credentials and database connection string detector for JSXRay."""

import base64
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
from jsxray.utils.helpers import mask_secret


class CredentialAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "credentials"

    DB_URI_REGEX = re.compile(
        r"\b((?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|mariadb|mssql|oracle|sqlite|amqp)://(?:[^:]+):([^@]+)@([a-zA-Z0-9_\-\.]+)(?::\d+)?(?:/[^\s\"'`]*)?)\b",
        re.I,
    )
    BASIC_AUTH_REGEX = re.compile(r"Basic\s+([A-Za-z0-9+/=]{10,})", re.I)

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

            if not val:
                continue

            # 1. Database Connection Strings with Credentials
            db_match = self.DB_URI_REGEX.search(val)
            if db_match:
                full_uri = db_match.group(1)
                password = db_match.group(2)
                host = db_match.group(3)
                masked_uri = full_uri.replace(f":{password}@", f":{mask_secret(password)}@")

                line, col = get_node_line_col(node)
                findings.append(
                    Finding(
                        type=FindingType.CREDENTIAL,
                        value=masked_uri,
                        normalized_value=masked_uri,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.DETECTED,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line,
                        column=col,
                        snippet=get_node_snippet(node, code_lines),
                        original_source=get_node_text(node, code_bytes).strip(),
                        reconstructed_source=masked_uri,
                        discovery_method="AST analysis",
                        tags=["credential", "database-url", "connection-string"],
                        extra_data={"host": host, "raw_uri": full_uri, "masked_uri": masked_uri},
                    )
                )

            # 2. Basic Auth Headers
            basic_match = self.BASIC_AUTH_REGEX.search(val)
            if basic_match:
                b64_str = basic_match.group(1)
                decoded_cred = ""
                try:
                    decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
                    if ":" in decoded:
                        u, p = decoded.split(":", 1)
                        decoded_cred = f"{u}:{mask_secret(p)}"
                except Exception:
                    pass

                line, col = get_node_line_col(node)
                findings.append(
                    Finding(
                        type=FindingType.CREDENTIAL,
                        value=f"Basic Auth ({decoded_cred or 'encoded'})",
                        normalized_value=f"Basic Auth {b64_str[:6]}***",
                        confidence=Confidence.HIGH,
                        status=FindingStatus.DETECTED,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line,
                        column=col,
                        snippet=get_node_snippet(node, code_lines),
                        original_source=get_node_text(node, code_bytes).strip(),
                        reconstructed_source=decoded_cred or val,
                        discovery_method="AST analysis",
                        tags=["credential", "basic-auth", "auth-indicator"],
                        extra_data={"decoded_credential": decoded_cred, "raw_header": val},
                    )
                )

            # 3. Hardcoded credentials in object literals: { username: "admin", password: "SecretPassword123" }
            if node.type == "object":
                props = get_object_properties(node, code_bytes)
                if ("username" in props or "user" in props or "email" in props) and (
                    "password" in props or "passwd" in props or "secret" in props
                ):
                    pwd_node = props.get("password") or props.get("passwd") or props.get("secret")
                    if pwd_node and pwd_node.type in ("string", "string_fragment"):
                        pwd_val = extract_string_literal(pwd_node, code_bytes)
                        if pwd_val and len(pwd_val) >= 4 and not pwd_val.startswith(("{", "$")):
                            # Skip dummy placeholder values like "password" or empty
                            status = FindingStatus.DETECTED
                            if pwd_val.lower() in ("password", "123456", "admin", "test", "dummy"):
                                status = FindingStatus.TEST_VALUE

                            user_node = props.get("username") or props.get("user") or props.get("email")
                            user_val = extract_string_literal(user_node, code_bytes) or "user" if user_node else "user"
                            masked_cred = f"{user_val}:{mask_secret(pwd_val)}"

                            line, col = get_node_line_col(node)
                            findings.append(
                                Finding(
                                    type=FindingType.CREDENTIAL,
                                    value=masked_cred,
                                    normalized_value=f"{user_val}:***",
                                    confidence=Confidence.MEDIUM,
                                    status=status,
                                    source_file=source.file_path,
                                    source_url=source.url,
                                    line=line,
                                    column=col,
                                    snippet=get_node_snippet(node, code_lines),
                                    original_source=get_node_text(node, code_bytes).strip(),
                                    reconstructed_source=masked_cred,
                                    discovery_method="AST analysis",
                                    tags=["credential", "hardcoded-user-pass"],
                                    extra_data={"user": user_val, "masked_credential": masked_cred},
                                )
                            )

        return findings
