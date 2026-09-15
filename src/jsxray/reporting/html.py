"""Self-contained interactive HTML security report generator for JSXRay with static asset filtering."""

import html
import json
from typing import Any, Dict, List
from jsxray.models.scan import ScanResult


class HtmlReporter:
    """Renders a standalone, offline-capable professional security intelligence report."""

    def __init__(self, scan_result: ScanResult, relationships: Dict[str, Any] = None) -> None:
        self.scan_result = scan_result
        self.relationships = relationships or {}

    def generate(self) -> str:
        data = self.scan_result.to_dict()
        stats = data["statistics"]
        meta = data["metadata"]
        sources = data["sources"]
        findings = data["findings"]
        errors = data["errors"]
        warnings = data["warnings"]

        # Map findings into category-friendly format
        type_mapping = {
            "api_endpoint": "API Endpoint",
            "url_route": "URL / Route",
            "parameter": "Parameter",
            "api_host": "Subdomain / Host",
            "secret": "Secret",
            "credential": "Credential",
            "authentication": "Authentication",
            "graphql": "GraphQL",
            "websocket": "WebSocket",
            "sse": "WebSocket",
            "internal_host": "Internal Infrastructure",
            "dangerous_js": "Dangerous JS",
            "technology": "Technology",
            "source_map": "Source Map",
            "dynamic_import": "Dynamic Import / Chunk",
            "security_candidate": "Testing Candidate",
            "static_resource": "Static Resource",
            "external_url": "External Reference",
        }

        formatted_findings = []
        for f in findings:
            category_name = type_mapping.get(f.get("type"), f.get("type"))
            sources_list = []
            if f.get("occurrences"):
                for occ in f["occurrences"]:
                    sources_list.append({
                        "file": occ.get("source_file") or occ.get("source_url") or f.get("source_file") or f.get("source_url") or "unknown",
                        "line": occ.get("line") or f.get("line") or 1,
                        "column": occ.get("column") or f.get("column") or 1,
                        "snippet": occ.get("snippet") or f.get("snippet") or "",
                        "raw_value": occ.get("raw_value") or f.get("value") or "",
                    })
            else:
                sources_list.append({
                    "file": f.get("source_file") or f.get("source_url") or "unknown",
                    "line": f.get("line") or 1,
                    "column": f.get("column") or 1,
                    "snippet": f.get("snippet") or "",
                    "raw_value": f.get("value") or "",
                })

            is_static = bool(
                f.get("type") in ("static_resource", "source_map", "dynamic_import")
                or f.get("extra_data", {}).get("is_static_asset", False)
                or "static-asset" in f.get("tags", [])
            )
            asset_type = f.get("extra_data", {}).get("asset_type", "")

            formatted_findings.append({
                "id": f.get("finding_id"),
                "type": category_name,
                "raw_type": f.get("type"),
                "value": f.get("value"),
                "normalizedValue": f.get("normalized_value"),
                "confidence": f.get("confidence", "Medium"),
                "status": f.get("status", "Detected"),
                "tags": f.get("tags", []),
                "sources": sources_list,
                "isStaticAsset": is_static,
                "assetType": asset_type,
                "provenance": {
                    "origin": "Static AST Analysis" if f.get("discovery_method") == "AST analysis" else f.get("discovery_method", "Static"),
                    "transformationChain": f.get("extra_data", {}).get("transformations", ["Static Extraction"]),
                },
                "metadata": f.get("extra_data", {}),
                "assessment": f.get("extra_data", {}).get("rationale") or f.get("extra_data", {}).get("category") or f"Discovered {category_name.lower()}",
            })

        # JSON Data Payload for Client-Side Interactivity
        json_payload = json.dumps({
            "metadata": meta,
            "statistics": stats,
            "sources": sources,
            "findings": formatted_findings,
            "relationships": self.relationships,
            "errors": errors,
            "warnings": warnings,
        }, default=str)

        target_name = meta.get("target_input", "JavaScript Scan")
        target_domain_val = meta.get("target_domain")
        domain_tag = f"&bull; Target Scope: <span style='color:var(--accent); font-weight:700;'>*.{html.escape(target_domain_val)}</span>" + (" <small style='color:var(--text-muted);'>(Inferred)</small>" if meta.get('inferred_domain') else "") if target_domain_val else "&bull; Scope: <span style='color:var(--text-muted);'>No target domain specified (-d domain.com)</span>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>JSXRay Report — {html.escape(target_name)}</title>
  <style>
    :root {{
      --bg-main: #0B0F19;
      --bg-card: #111827;
      --bg-card-hover: #1F2937;
      --border: #374151;
      --border-accent: #3B82F6;
      --text-main: #F9FAFB;
      --text-muted: #9CA3AF;
      --accent: #38BDF8;
      --accent-glow: rgba(56, 189, 248, 0.15);
      --success: #10B981;
      --warning: #F59E0B;
      --danger: #EF4444;
      --purple: #A855F7;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg-main);
      color: var(--text-main);
      font-family: var(--font-sans);
      line-height: 1.5;
      display: flex;
      height: 100vh;
      overflow: hidden;
      font-size: 13px;
    }}

    /* Sidebar */
    .sidebar {{
      width: 260px;
      background-color: var(--bg-card);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
    }}
    .brand {{
      padding: 18px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .brand-icon {{
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, #38BDF8, #6366F1);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      color: white;
      font-family: var(--font-mono);
      font-size: 14px;
    }}
    .brand-title {{
      font-size: 1.1rem;
      font-weight: 700;
      letter-spacing: -0.5px;
    }}
    .brand-sub {{
      font-size: 0.68rem;
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: 600;
    }}
    .nav-list {{
      list-style: none;
      padding: 12px 8px;
      overflow-y: auto;
      flex-grow: 1;
    }}
    .nav-item {{
      padding: 8px 12px;
      margin-bottom: 3px;
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
      color: var(--text-muted);
      font-size: 0.86rem;
      transition: all 0.15s ease;
    }}
    .nav-item:hover {{
      background-color: var(--bg-card-hover);
      color: var(--text-main);
    }}
    .nav-item.active {{
      border-left: 3px solid var(--accent);
      background-color: rgba(56, 189, 248, 0.08);
      color: var(--accent);
      font-weight: 600;
    }}
    .nav-badge {{
      background: #1E293B;
      padding: 2px 7px;
      border-radius: 12px;
      font-size: 0.72rem;
      font-family: var(--font-mono);
      color: var(--text-muted);
    }}
    .nav-item.active .nav-badge {{
      color: var(--accent);
      background: rgba(56, 189, 248, 0.15);
    }}

    /* Main Content */
    .main {{
      flex-grow: 1;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }}

    /* Header */
    .header {{
      padding: 14px 24px;
      background-color: var(--bg-card);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
    }}
    .target-info h2 {{
      font-size: 1.05rem;
      font-weight: 600;
    }}
    .target-info p {{
      font-size: 0.75rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
      margin-top: 2px;
    }}
    .search-box {{
      flex-grow: 1;
      max-width: 480px;
      position: relative;
    }}
    .search-input {{
      width: 100%;
      background: var(--bg-main);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 7px 12px 7px 34px;
      color: var(--text-main);
      font-size: 0.85rem;
      outline: none;
      transition: border-color 0.2s;
    }}
    .search-input:focus {{
      border-color: var(--accent);
      box-shadow: 0 0 0 2px var(--accent-glow);
    }}
    .search-icon {{
      position: absolute;
      left: 10px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      font-size: 0.85rem;
    }}

    /* Content Area */
    .content {{
      flex-grow: 1;
      overflow-y: auto;
      padding: 24px;
    }}

    /* Dashboard Metrics */
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 14px;
      margin-bottom: 24px;
    }}
    .metric-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
      cursor: pointer;
      transition: transform 0.15s, border-color 0.15s;
    }}
    .metric-card:hover {{
      transform: translateY(-2px);
      border-color: var(--accent);
    }}
    .metric-title {{
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }}
    .metric-val {{
      font-size: 1.45rem;
      font-weight: 700;
      font-family: var(--font-mono);
    }}

    /* Filter Bar */
    .filter-bar {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }}
    .filter-select {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 12px;
      color: var(--text-main);
      font-size: 0.8rem;
      outline: none;
    }}
    .filter-btn {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 14px;
      color: var(--text-main);
      font-size: 0.8rem;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: background 0.15s;
    }}
    .filter-btn:hover {{
      background: var(--bg-card-hover);
      border-color: var(--accent);
    }}

    /* Segmented Filter Control */
    .filter-segmented {{
      display: flex;
      background: var(--bg-main);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 2px;
      gap: 2px;
    }}
    .segmented-btn {{
      background: none;
      border: none;
      color: var(--text-muted);
      padding: 5px 12px;
      border-radius: 4px;
      font-size: 0.78rem;
      cursor: pointer;
      font-weight: 500;
      transition: all 0.15s ease;
    }}
    .segmented-btn:hover {{
      color: var(--text-main);
    }}
    .segmented-btn.active {{
      background: var(--bg-card-hover);
      color: var(--accent);
      font-weight: 600;
      box-shadow: 0 1px 3px rgba(0,0,0,0.3);
    }}

    /* Notice Banner for Hidden Static Assets */
    .filter-notice {{
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.2);
      border-radius: 6px;
      padding: 8px 14px;
      font-size: 0.82rem;
      color: var(--accent);
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .filter-notice-btn {{
      background: none;
      border: 1px solid rgba(56, 189, 248, 0.4);
      color: var(--accent);
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 0.76rem;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.15s ease;
    }}
    .filter-notice-btn:hover {{
      background: rgba(56, 189, 248, 0.2);
    }}

    /* Data Table */
    .table-container {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }}
    th {{
      background: #161F30;
      padding: 10px 14px;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
    }}
    td {{
      padding: 10px 14px;
      border-bottom: 1px solid rgba(55, 65, 81, 0.5);
      font-size: 0.84rem;
    }}
    tbody tr:hover {{
      background-color: var(--bg-card-hover);
      cursor: pointer;
    }}

    /* Badges */
    .method-badge {{
      font-family: var(--font-mono);
      font-size: 0.72rem;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
    }}
    .method-get {{ background: rgba(16, 185, 129, 0.15); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.3); }}
    .method-post {{ background: rgba(59, 130, 246, 0.15); color: #60A5FA; border: 1px solid rgba(59, 130, 246, 0.3); }}
    .method-put {{ background: rgba(245, 158, 11, 0.15); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.3); }}
    .method-delete {{ background: rgba(239, 68, 68, 0.15); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
    .method-patch {{ background: rgba(168, 85, 247, 0.15); color: #C084FC; border: 1px solid rgba(168, 85, 247, 0.3); }}

    .conf-badge {{
      font-size: 0.72rem;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
    }}
    .conf-high {{ background: rgba(16, 185, 129, 0.15); color: #34D399; }}
    .conf-medium {{ background: rgba(245, 158, 11, 0.15); color: #FBBF24; }}
    .conf-low {{ background: rgba(156, 163, 175, 0.15); color: #9CA3AF; }}

    .tag-badge {{
      background: #1E293B;
      color: #94A3B8;
      font-size: 0.7rem;
      padding: 1px 6px;
      border-radius: 4px;
      margin-right: 4px;
      display: inline-block;
    }}
    .tag-static {{
      background: rgba(148, 163, 184, 0.12);
      color: #94A3B8;
      border: 1px solid rgba(148, 163, 184, 0.25);
    }}
    .tag-endpoint {{
      background: rgba(56, 189, 248, 0.12);
      color: #38BDF8;
      border: 1px solid rgba(56, 189, 248, 0.25);
    }}

    .loc-badge {{
      background: rgba(56, 189, 248, 0.1);
      color: #38BDF8;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      padding: 2px 7px;
      border-radius: 4px;
      border: 1px solid rgba(56, 189, 248, 0.25);
      display: inline-flex;
      align-items: center;
      gap: 4px;
      max-width: 280px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .loc-line {{
      color: #FBBF24;
      font-weight: 700;
    }}

    .secret-masked {{
      font-family: var(--font-mono);
      background: rgba(239, 68, 68, 0.1);
      color: #F87171;
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid rgba(239, 68, 68, 0.2);
    }}

    /* Leak Location Card in Drawer */
    .leak-card {{
      background: var(--bg-main);
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent);
      border-radius: 6px;
      padding: 12px 14px;
      margin-bottom: 10px;
    }}
    .leak-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }}
    .leak-file {{
      font-family: var(--font-mono);
      color: var(--text-main);
      font-size: 0.82rem;
      font-weight: 600;
      word-break: break-all;
    }}
    .leak-line-pill {{
      background: rgba(245, 158, 11, 0.15);
      color: #FBBF24;
      border: 1px solid rgba(245, 158, 11, 0.3);
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.72rem;
      font-family: var(--font-mono);
      font-weight: 700;
      flex-shrink: 0;
    }}
    .code-snippet {{
      background: #060911;
      border: 1px solid #1E293B;
      border-radius: 4px;
      padding: 8px 10px;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      color: #E2E8F0;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }}

    /* Evidence Slide-in Drawer */
    .drawer-overlay {{
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.65);
      backdrop-filter: blur(2px);
      display: none;
      justify-content: flex-end;
      z-index: 100;
    }}
    .drawer {{
      width: 660px;
      max-width: 92vw;
      background: var(--bg-card);
      border-left: 1px solid var(--border);
      height: 100%;
      overflow-y: auto;
      padding: 24px;
      display: flex;
      flex-direction: column;
      box-shadow: -10px 0 30px rgba(0,0,0,0.5);
    }}
    .drawer-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 18px;
      padding-bottom: 14px;
      border-bottom: 1px solid var(--border);
    }}
    .drawer-close {{
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 1.5rem;
      cursor: pointer;
      padding: 0 8px;
    }}
    .drawer-close:hover {{ color: var(--text-main); }}
    .drawer-section {{
      margin-bottom: 18px;
    }}
    .drawer-section h4 {{
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--accent);
      margin-bottom: 8px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .code-block {{
      background: var(--bg-main);
      padding: 12px;
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 0.82rem;
      overflow-x: auto;
      border: 1px solid var(--border);
      color: #E2E8F0;
      white-space: pre-wrap;
      word-break: break-all;
    }}

    .drawer-btn-row {{
      display: flex;
      gap: 10px;
      margin-top: 8px;
    }}
    .action-btn {{
      background: #1F2937;
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 6px 12px;
      border-radius: 4px;
      font-size: 0.8rem;
      cursor: pointer;
    }}
    .action-btn:hover {{
      border-color: var(--accent);
      color: var(--accent);
    }}

    /* Tree View for Relationships */
    .tree-box {{
      font-family: var(--font-mono);
      font-size: 0.82rem;
      line-height: 1.8;
      background: var(--bg-main);
      padding: 16px;
      border-radius: 6px;
      border: 1px solid var(--border);
    }}
    .tree-host {{
      color: var(--accent);
      font-weight: 700;
    }}
    .tree-ep {{
      color: #34D399;
      padding-left: 20px;
    }}

    /* Floating Toast Notification */
    .toast-container {{
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #1E293B;
      border: 1px solid var(--accent);
      color: #F8FAFC;
      padding: 10px 18px;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 600;
      box-shadow: 0 4px 16px rgba(0,0,0,0.5);
      z-index: 9999;
      display: none;
      align-items: center;
      gap: 8px;
    }}
  </style>
</head>
<body>

  <!-- Floating Toast Notification -->
  <div class="toast-container" id="toastNotification"></div>

  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-icon">X</div>
      <div>
        <div class="brand-title">JSXRay</div>
        <div class="brand-sub">Security Intelligence</div>
      </div>
    </div>
    <ul class="nav-list" id="navList">
      <li class="nav-item active" data-tab="dashboard">
        <span>📊 Dashboard</span>
      </li>
      <li class="nav-item" data-tab="API Endpoint">
        <span>📡 API Endpoints</span>
        <span class="nav-badge" id="badge-endpoints">0</span>
      </li>
      <li class="nav-item" data-tab="URL / Route">
        <span>🌐 Application Routes</span>
        <span class="nav-badge" id="badge-urls">0</span>
      </li>
      <li class="nav-item" data-tab="Parameter">
        <span>🏷️ Parameters</span>
        <span class="nav-badge" id="badge-parameters">0</span>
      </li>
      <li class="nav-item" data-tab="Subdomain / Host">
        <span>🏢 Subdomains & API Hosts</span>
        <span class="nav-badge" id="badge-hosts">0</span>
      </li>
      <li class="nav-item" data-tab="Secret">
        <span>🔑 Secrets & Tokens</span>
        <span class="nav-badge" id="badge-secrets">0</span>
      </li>
      <li class="nav-item" data-tab="Credential">
        <span>🛡️ Credentials</span>
        <span class="nav-badge" id="badge-credentials">0</span>
      </li>
      <li class="nav-item" data-tab="Testing Candidate">
        <span>🎯 Testing Candidates</span>
        <span class="nav-badge" id="badge-candidates">0</span>
      </li>
      <li class="nav-item" data-tab="Authentication">
        <span>🔐 Authentication</span>
        <span class="nav-badge" id="badge-auth">0</span>
      </li>
      <li class="nav-item" data-tab="GraphQL">
        <span>⚡ GraphQL</span>
        <span class="nav-badge" id="badge-graphql">0</span>
      </li>
      <li class="nav-item" data-tab="WebSocket">
        <span>🔌 WebSockets & SSE</span>
        <span class="nav-badge" id="badge-websockets">0</span>
      </li>
      <li class="nav-item" data-tab="Internal Infrastructure">
        <span>🏠 Infrastructure</span>
        <span class="nav-badge" id="badge-infra">0</span>
      </li>
      <li class="nav-item" data-tab="Dangerous JS">
        <span>⚠️ Dangerous Sinks</span>
        <span class="nav-badge" id="badge-dangerous">0</span>
      </li>
      <li class="nav-item" data-tab="Technology">
        <span>📦 Technologies</span>
        <span class="nav-badge" id="badge-tech">0</span>
      </li>
      <li class="nav-item" data-tab="Source Map">
        <span>🗺️ Source Maps</span>
        <span class="nav-badge" id="badge-maps">0</span>
      </li>
      <li class="nav-item" data-tab="Dynamic Import / Chunk">
        <span>🧩 Dynamic Imports / Chunks</span>
        <span class="nav-badge" id="badge-dynamic-imports">0</span>
      </li>
      <li class="nav-item" data-tab="Static Resource">
        <span>📁 Static Resources</span>
        <span class="nav-badge" id="badge-static-assets">0</span>
      </li>
      <li class="nav-item" data-tab="External Reference">
        <span>🔗 External References</span>
        <span class="nav-badge" id="badge-external-urls">0</span>
      </li>
      <li class="nav-item" data-tab="sources">
        <span>📄 Analyzed Sources</span>
        <span class="nav-badge" id="badge-sources">0</span>
      </li>
      <li class="nav-item" data-tab="relationships">
        <span>🌳 Correlation Tree</span>
      </li>
    </ul>
    <div style="padding: 12px 16px; border-top: 1px solid var(--border); font-size: 0.72rem; color: var(--text-muted);">
      Created by <strong style="color: var(--accent);">Salman</strong> (<a href="https://github.com/bashx7" target="_blank" style="color: var(--text-muted); text-decoration: none;">@bashx7</a>)
    </div>
  </aside>

  <!-- Main View -->
  <main class="main">
    <header class="header">
      <div class="target-info">
        <h2 id="viewTitle">Dashboard Overview</h2>
        <p>Target: {html.escape(target_name)} &bull; Mode: {html.escape(meta.get('input_mode', ''))} {domain_tag}</p>
      </div>
      <div class="search-box">
        <span class="search-icon">🔍</span>
        <input type="text" class="search-input" id="globalSearch" placeholder="Search endpoints, parameters, secrets, hosts, files...">
      </div>
    </header>

    <div class="content">

      <!-- DASHBOARD VIEW -->
      <div id="dashboardView">
        <div class="metrics-grid">
          <div class="metric-card" onclick="switchTab('sources')">
            <div class="metric-title">JS Files Analyzed</div>
            <div class="metric-val" id="metricFiles">{stats.get('analyzed_sources', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('API Endpoint')">
            <div class="metric-title">API Endpoints</div>
            <div class="metric-val" id="metricEndpoints" style="color: #38BDF8;">{stats.get('api_endpoints', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('URL / Route')">
            <div class="metric-title">Application Routes</div>
            <div class="metric-val" id="metricRoutes" style="color: #34D399;">{stats.get('url_routes', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('Parameter')">
            <div class="metric-title">Parameters</div>
            <div class="metric-val" id="metricParameters">{stats.get('parameters', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('Secret')">
            <div class="metric-title">Secrets & Tokens</div>
            <div class="metric-val" id="metricSecrets" style="color: #F87171;">{stats.get('secrets', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('Credential')">
            <div class="metric-title">Credentials</div>
            <div class="metric-val" id="metricCredentials" style="color: #FBBF24;">{stats.get('credentials', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('Testing Candidate')">
            <div class="metric-title">Testing Candidates</div>
            <div class="metric-val" id="metricCandidates" style="color: #F59E0B;">{stats.get('security_candidates', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('Subdomain / Host')">
            <div class="metric-title">Subdomains / Hosts</div>
            <div class="metric-val" id="metricHosts" style="color: #60A5FA;">{stats.get('api_hosts', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('GraphQL')">
            <div class="metric-title">GraphQL Ops</div>
            <div class="metric-val" id="metricGraphql">{stats.get('graphql_endpoints', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('WebSocket')">
            <div class="metric-title">WebSockets / SSE</div>
            <div class="metric-val" id="metricWs">{stats.get('websockets', 0) + stats.get('sse_endpoints', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('Internal Infrastructure')">
            <div class="metric-title">Internal Hosts</div>
            <div class="metric-val" id="metricInfra">{stats.get('internal_hosts', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('Dangerous JS')">
            <div class="metric-title">Dangerous Sinks</div>
            <div class="metric-val" id="metricDangerous">{stats.get('dangerous_js', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('Technology')">
            <div class="metric-title">Technologies</div>
            <div class="metric-val" id="metricTech">{stats.get('technologies', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('Static Resource')">
            <div class="metric-title">Static Resources</div>
            <div class="metric-val" id="metricStaticAssets" style="color: #94A3B8;">{stats.get('static_resources', 0)}</div>
          </div>
          <div class="metric-card" onclick="switchTab('External Reference')">
            <div class="metric-title">External References</div>
            <div class="metric-val" id="metricExternalUrls" style="color: #94A3B8;">{stats.get('external_urls', 0)}</div>
          </div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 12px;">
          <h3 style="font-size: 1.05rem; font-weight:600;">📡 Top Discovered API Endpoints</h3>
          <button class="filter-btn" onclick="copyAllEndpoints()" style="color: var(--accent); border-color: rgba(56, 189, 248, 0.4); font-weight:600;">📋 Copy Endpoints</button>
        </div>
        <div class="table-container" style="margin-bottom: 24px;">
          <table id="topEndpointsTable">
            <thead>
              <tr>
                <th style="width: 80px;">Method</th>
                <th>Endpoint Path</th>
                <th>Confidence</th>
                <th>Tags</th>
                <th>Occurrences</th>
                <th>Discovery Location</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>
      </div>

      <!-- CATEGORY TABLE VIEW -->
      <div id="categoryView" style="display: none;">
        <div class="filter-bar">
          <!-- Static Asset Segmented Filter (Shown on URL/Route and Static tabs) -->
          <div class="filter-segmented" id="assetFilterGroup">
            <button class="segmented-btn active" id="btnFilterDynamic" onclick="setAssetFilter('dynamic')">🎯 Dynamic Endpoints & Routes</button>
            <button class="segmented-btn" id="btnFilterStatic" onclick="setAssetFilter('static')">📁 Static Files (.js, .css, etc.)</button>
            <button class="segmented-btn" id="btnFilterAll" onclick="setAssetFilter('all')">🌐 All Items</button>
          </div>

          <!-- Subdomain & Host Scope Filter (Shown on Subdomain / Host tab) -->
          <div class="filter-segmented" id="hostFilterGroup" style="display: none;">
            <button class="segmented-btn active" id="btnFilterAllHosts" onclick="setHostFilter('all')">🌐 All Discovered Hosts</button>
            <button class="segmented-btn" id="btnFilterInScopeHosts" onclick="setHostFilter('in-scope')">🎯 In-Scope Subdomains</button>
            <button class="segmented-btn" id="btnFilterThirdPartyHosts" onclick="setHostFilter('third-party')">🏢 Third-Party APIs</button>
          </div>

          <select class="filter-select" id="filterConfidence">
            <option value="">All Confidences</option>
            <option value="High">High Confidence</option>
            <option value="Medium">Medium Confidence</option>
            <option value="Low">Low Confidence</option>
          </select>
          <select class="filter-select" id="filterStatus">
            <option value="">All Statuses</option>
            <option value="Detected">Detected</option>
            <option value="Potential">Potential</option>
            <option value="Test-value">Test-value</option>
          </select>
          <button class="filter-btn" id="btnCopyCategory" onclick="copyCurrentCategoryList()" style="color: var(--accent); border-color: rgba(56, 189, 248, 0.4); font-weight:600;">📋 Copy List</button>
          <button class="filter-btn" onclick="exportCategoryData()">Export JSON</button>
        </div>

        <!-- Target Domain Scope Notice Banner -->
        <div class="filter-notice" id="domainScopeNotice" style="display: none;">
          <span id="domainScopeNoticeText"></span>
        </div>

        <!-- Dynamic vs Static Notice Banner -->
        <div class="filter-notice" id="filterNotice" style="display: none;">
          <span id="filterNoticeText">⚡ Static asset files (.js, .css, images) are currently hidden.</span>
          <button class="filter-notice-btn" id="filterNoticeBtn" onclick="setAssetFilter('static')">Show Static Files</button>
        </div>

        <div class="table-container">
          <table id="findingsTable">
            <thead>
              <tr id="tableHeaders">
                <th>Finding Value</th>
                <th>Confidence</th>
                <th>Status</th>
                <th>Tags</th>
                <th>Occurrences</th>
                <th>Leak / Source Location</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>
      </div>

      <!-- SOURCES VIEW -->
      <div id="sourcesView" style="display: none;">
        <div class="table-container">
          <table id="sourcesTable">
            <thead>
              <tr>
                <th>Source Identifier / File</th>
                <th>Size</th>
                <th>Status</th>
                <th>Encoding</th>
                <th>Issues / Warnings</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>
      </div>

      <!-- RELATIONSHIPS VIEW -->
      <div id="relationshipsView" style="display: none;">
        <div class="table-container" style="padding: 16px;">
          <h3 style="font-size: 1.05rem; margin-bottom: 12px; font-weight:600;">🔗 Correlated Host-to-Endpoint Attack Surface</h3>
          <div id="treeContainer" class="tree-box"></div>
        </div>
      </div>

    </div>
  </main>

  <!-- Evidence Slide-in Drawer -->
  <div class="drawer-overlay" id="drawerOverlay">
    <div class="drawer" id="drawer">
      <div class="drawer-header">
        <div>
          <h3 id="drawerTitle" style="font-size: 1.15rem; word-break: break-all;">Finding Details</h3>
          <span id="drawerType" style="font-size: 0.78rem; color: var(--accent); font-family: var(--font-mono);"></span>
        </div>
        <button class="drawer-close" id="drawerClose">&times;</button>
      </div>

      <!-- Leak Location Cards Section -->
      <div class="drawer-section">
        <h4>📍 Exact Leak Location & Source Evidence (<span id="drawerSourceCount">0</span> Occurrences)</h4>
        <div id="drawerLeakCards"></div>
      </div>

      <div class="drawer-section">
        <h4>🔍 Assessment & Context</h4>
        <p id="drawerAssessment" style="color: var(--text-muted); font-size: 0.88rem;"></p>
      </div>

      <div class="drawer-section">
        <h4>🔑 Value / Expression</h4>
        <div class="code-block" id="drawerValue"></div>
        <div class="drawer-btn-row">
          <button class="action-btn" id="drawerCopyBtn">Copy Value</button>
          <button class="action-btn" id="drawerRevealBtn" style="display:none;">Reveal Raw Secret</button>
        </div>
      </div>

      <div class="drawer-section">
        <h4>⚙️ Provenance & AST Transformations</h4>
        <div class="code-block" id="drawerProvenance"></div>
      </div>

      <div class="drawer-section" id="drawerExtraSection">
        <h4>📊 Analyzer Metadata</h4>
        <div class="code-block" id="drawerExtra" style="max-height: 200px;"></div>
      </div>
    </div>
  </div>

  <script>
    const SCAN_DATA = {json_payload};
    const findings = SCAN_DATA.findings || [];
    const sources = SCAN_DATA.sources || [];
    const relationships = SCAN_DATA.relationships || {{}};
    const meta = SCAN_DATA.metadata || {{}};

    let currentTab = 'dashboard';
    let searchQuery = '';
    let confidenceFilter = '';
    let statusFilter = '';
    let assetFilter = 'dynamic'; // 'dynamic' | 'static' | 'all'
    let hostFilter = 'all'; // 'all' | 'in-scope' | 'third-party'
    let activeFinding = null;

    function showToast(msg) {{
      const toast = document.getElementById('toastNotification');
      if (toast) {{
        toast.textContent = msg;
        toast.style.display = 'flex';
        setTimeout(() => {{
          toast.style.display = 'none';
        }}, 2500);
      }} else {{
        alert(msg);
      }}
    }}

    function updateBadges() {{
      const counts = {{}};

      findings.forEach(f => {{
        counts[f.type] = (counts[f.type] || 0) + 1;
      }});

      document.getElementById('badge-endpoints').textContent = counts['API Endpoint'] || 0;
      document.getElementById('badge-urls').textContent = counts['URL / Route'] || 0;
      document.getElementById('badge-parameters').textContent = counts['Parameter'] || 0;
      document.getElementById('badge-hosts').textContent = counts['Subdomain / Host'] || 0;
      document.getElementById('badge-secrets').textContent = counts['Secret'] || 0;
      document.getElementById('badge-credentials').textContent = counts['Credential'] || 0;
      document.getElementById('badge-candidates').textContent = counts['Testing Candidate'] || 0;
      document.getElementById('badge-graphql').textContent = counts['GraphQL'] || 0;
      document.getElementById('badge-websockets').textContent = counts['WebSocket'] || 0;
      document.getElementById('badge-auth').textContent = counts['Authentication'] || 0;
      document.getElementById('badge-infra').textContent = counts['Internal Infrastructure'] || 0;
      document.getElementById('badge-dangerous').textContent = counts['Dangerous JS'] || 0;
      document.getElementById('badge-tech').textContent = counts['Technology'] || 0;
      document.getElementById('badge-maps').textContent = counts['Source Map'] || 0;
      const dynImpEl = document.getElementById('badge-dynamic-imports');
      if (dynImpEl) dynImpEl.textContent = counts['Dynamic Import / Chunk'] || 0;
      const staticEl = document.getElementById('badge-static-assets');
      if (staticEl) staticEl.textContent = counts['Static Resource'] || 0;
      const extEl = document.getElementById('badge-external-urls');
      if (extEl) extEl.textContent = counts['External Reference'] || 0;
      document.getElementById('badge-sources').textContent = sources.length;

      const elFiles = document.getElementById('metricFiles');
      if (elFiles) elFiles.textContent = sources.length;
      const elEndpoints = document.getElementById('metricEndpoints');
      if (elEndpoints) elEndpoints.textContent = counts['API Endpoint'] || 0;
      const elRoutes = document.getElementById('metricRoutes');
      if (elRoutes) elRoutes.textContent = counts['URL / Route'] || 0;
      const elParams = document.getElementById('metricParameters');
      if (elParams) elParams.textContent = counts['Parameter'] || 0;
      const elSecrets = document.getElementById('metricSecrets');
      if (elSecrets) elSecrets.textContent = counts['Secret'] || 0;
      const elCreds = document.getElementById('metricCredentials');
      if (elCreds) elCreds.textContent = counts['Credential'] || 0;
      const elCand = document.getElementById('metricCandidates');
      if (elCand) elCand.textContent = counts['Testing Candidate'] || 0;
      const elHosts = document.getElementById('metricHosts');
      if (elHosts) elHosts.textContent = counts['Subdomain / Host'] || 0;
      const elGql = document.getElementById('metricGraphql');
      if (elGql) elGql.textContent = counts['GraphQL'] || 0;
      const elWs = document.getElementById('metricWs');
      if (elWs) elWs.textContent = counts['WebSocket'] || 0;
      const elInfra = document.getElementById('metricInfra');
      if (elInfra) elInfra.textContent = counts['Internal Infrastructure'] || 0;
      const elDang = document.getElementById('metricDangerous');
      if (elDang) elDang.textContent = counts['Dangerous JS'] || 0;
      const elTech = document.getElementById('metricTech');
      if (elTech) elTech.textContent = counts['Technology'] || 0;
      const elStatic = document.getElementById('metricStaticAssets');
      if (elStatic) elStatic.textContent = counts['Static Resource'] || 0;
      const elExt = document.getElementById('metricExternalUrls');
      if (elExt) elExt.textContent = counts['External Reference'] || 0;
    }}

    function renderDashboard() {{
      // Only show real API endpoints on dashboard (exclude any static assets)
      const endpoints = findings.filter(f => f.type === 'API Endpoint' && !f.isStaticAsset).slice(0, 20);
      const tbody = document.querySelector('#topEndpointsTable tbody');
      tbody.innerHTML = '';

      if (!endpoints.length) {{
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:20px;">No dynamic API endpoints discovered</td></tr>';
        return;
      }}

      endpoints.forEach(ep => {{
        const tr = document.createElement('tr');
        tr.onclick = () => openDrawer(ep);

        const method = ep.metadata?.method || 'GET';
        const mClass = 'method-' + method.toLowerCase();
        const firstSrc = ep.sources[0] || {{}};
        const fileName = (firstSrc.file || 'unknown').split('/').pop();
        const lineNum = firstSrc.line || 1;

        tr.innerHTML = `
          <td><span class="method-badge ${{mClass}}">${{escapeHtml(method)}}</span></td>
          <td style="font-family: var(--font-mono); font-weight: 600; color: #E2E8F0;">${{escapeHtml(ep.normalizedValue || ep.value)}}</td>
          <td><span class="conf-badge conf-${{ep.confidence.toLowerCase()}}">${{ep.confidence}}</span></td>
          <td>${{ep.tags.map(t => '<span class="tag-badge">' + escapeHtml(t) + '</span>').join('')}}</td>
          <td><span class="tag-badge">${{ep.sources.length}} occ</span></td>
          <td>
            <span class="loc-badge" title="${{escapeHtml(firstSrc.file)}}">
              📄 ${{escapeHtml(fileName)}} : <span class="loc-line">L${{lineNum}}</span>
            </span>
          </td>
        `;
        tbody.appendChild(tr);
      }});
    }}

    function setAssetFilter(filterMode) {{
      assetFilter = filterMode;
      document.querySelectorAll('#assetFilterGroup .segmented-btn').forEach(btn => btn.classList.remove('active'));
      if (filterMode === 'dynamic') document.getElementById('btnFilterDynamic')?.classList.add('active');
      else if (filterMode === 'static') document.getElementById('btnFilterStatic')?.classList.add('active');
      else if (filterMode === 'all') document.getElementById('btnFilterAll')?.classList.add('active');

      renderCategoryTable();
    }}

    function setHostFilter(filterMode) {{
      hostFilter = filterMode;
      document.querySelectorAll('#hostFilterGroup .segmented-btn').forEach(btn => btn.classList.remove('active'));
      if (filterMode === 'all') document.getElementById('btnFilterAllHosts')?.classList.add('active');
      else if (filterMode === 'in-scope') document.getElementById('btnFilterInScopeHosts')?.classList.add('active');
      else if (filterMode === 'third-party') document.getElementById('btnFilterThirdPartyHosts')?.classList.add('active');

      renderCategoryTable();
    }}

    function getCurrentlyFilteredFindings() {{
      let filtered = [];
      const isUrlTab = (currentTab === 'URL / Route' || currentTab === 'API Endpoint');
      const isHostTab = (currentTab === 'Subdomain / Host' || currentTab === 'API Host');

      if (currentTab === 'URL / Route') {{
        if (assetFilter === 'dynamic') {{
          filtered = findings.filter(f => f.type === 'URL / Route' && !f.isStaticAsset);
        }} else if (assetFilter === 'static') {{
          filtered = findings.filter(f => f.type === 'URL / Route' && f.isStaticAsset);
        }} else {{
          filtered = findings.filter(f => f.type === 'URL / Route');
        }}
      }} else if (currentTab === 'API Endpoint') {{
        if (assetFilter === 'dynamic') {{
          filtered = findings.filter(f => f.type === 'API Endpoint' && !f.isStaticAsset);
        }} else if (assetFilter === 'static') {{
          filtered = findings.filter(f => f.type === 'API Endpoint' && f.isStaticAsset);
        }} else {{
          filtered = findings.filter(f => f.type === 'API Endpoint');
        }}
      }} else if (isHostTab) {{
        const allHosts = findings.filter(f => f.type === 'Subdomain / Host' || f.type === 'API Host');
        if (hostFilter === 'in-scope') {{
          filtered = allHosts.filter(f => f.metadata?.is_in_scope === true || f.tags?.includes('in-scope'));
        }} else if (hostFilter === 'third-party') {{
          filtered = allHosts.filter(f => f.metadata?.category === 'Third-Party API Host' || f.tags?.includes('third-party-api-host'));
        }} else {{
          filtered = allHosts;
        }}
      }} else {{
        filtered = findings.filter(f => f.type === currentTab);
      }}

      if (searchQuery) {{
        const q = searchQuery.toLowerCase();
        filtered = filtered.filter(f =>
          f.value.toLowerCase().includes(q) ||
          (f.normalizedValue && f.normalizedValue.toLowerCase().includes(q)) ||
          f.tags.some(t => t.toLowerCase().includes(q)) ||
          f.sources.some(s => s.file.toLowerCase().includes(q) || s.snippet.toLowerCase().includes(q))
        );
      }}

      if (confidenceFilter) {{
        filtered = filtered.filter(f => f.confidence === confidenceFilter);
      }}

      if (statusFilter) {{
        filtered = filtered.filter(f => f.status === statusFilter);
      }}

      return filtered;
    }}

    function renderCategoryTable() {{
      const tbody = document.querySelector('#findingsTable tbody');
      tbody.innerHTML = '';

      const isUrlTab = (currentTab === 'URL / Route' || currentTab === 'API Endpoint');
      const isHostTab = (currentTab === 'Subdomain / Host' || currentTab === 'API Host');

      const assetFilterGroup = document.getElementById('assetFilterGroup');
      if (assetFilterGroup) {{
        assetFilterGroup.style.display = isUrlTab ? 'flex' : 'none';
      }}

      const hostFilterGroup = document.getElementById('hostFilterGroup');
      if (hostFilterGroup) {{
        hostFilterGroup.style.display = isHostTab ? 'flex' : 'none';
      }}

      // Scope Banner for Subdomains
      const scopeNotice = document.getElementById('domainScopeNotice');
      if (scopeNotice) {{
        if (isHostTab) {{
          if (meta.target_domain) {{
            const inScopeCount = findings.filter(f => (f.type === 'Subdomain / Host' || f.type === 'API Host') && (f.metadata?.is_in_scope === true || f.tags?.includes('in-scope'))).length;
            document.getElementById('domainScopeNoticeText').innerHTML = `🎯 Target Domain Scope: <strong>*.${{escapeHtml(meta.target_domain)}}</strong> &bull; ${{inScopeCount}} in-scope subdomains discovered.`;
            scopeNotice.style.display = 'flex';
          }} else {{
            document.getElementById('domainScopeNoticeText').innerHTML = `ℹ️ No target domain specified for scoping. Discovered hostnames are listed below. Use <code>-d domain.com</code> to scope in-domain subdomains.`;
            scopeNotice.style.display = 'flex';
          }}
        }} else {{
          scopeNotice.style.display = 'none';
        }}
      }}

      // Check for hidden static assets banner
      const notice = document.getElementById('filterNotice');
      if (notice) {{
        if (currentTab === 'URL / Route' && assetFilter === 'dynamic') {{
          const hiddenStaticCount = findings.filter(f => f.type === 'URL / Route' && f.isStaticAsset).length;
          if (hiddenStaticCount > 0) {{
            document.getElementById('filterNoticeText').textContent = `⚡ Displaying dynamic routes only (${{hiddenStaticCount}} static asset files like .js/.css are hidden).`;
            notice.style.display = 'flex';
          }} else {{
            notice.style.display = 'none';
          }}
        }} else {{
          notice.style.display = 'none';
        }}
      }}

      const filtered = getCurrentlyFilteredFindings();

      if (!filtered.length) {{
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:24px;">No items match criteria</td></tr>';
        return;
      }}

      // Sort: dynamic endpoints/routes first, then static files
      filtered.sort((a, b) => {{
        if (a.isStaticAsset !== b.isStaticAsset) return a.isStaticAsset ? 1 : -1;
        return (b.sources?.length || 1) - (a.sources?.length || 1);
      }});

      filtered.forEach(f => {{
        const tr = document.createElement('tr');
        tr.onclick = () => openDrawer(f);

        let valueDisplay = escapeHtml(f.value);
        if (f.type === 'API Endpoint' && f.metadata?.method) {{
          const mClass = 'method-' + f.metadata.method.toLowerCase();
          valueDisplay = `<span class="method-badge ${{mClass}}">${{escapeHtml(f.metadata.method)}}</span> ` + escapeHtml(f.normalizedValue || f.value);
        }} else if (f.type === 'Secret') {{
          valueDisplay = `<span class="secret-masked">${{escapeHtml(f.value)}}</span>`;
        }} else if ((f.type === 'Subdomain / Host' || f.type === 'API Host') && (f.metadata?.is_in_scope || f.tags?.includes('in-scope'))) {{
          valueDisplay = `<span style="color:var(--accent); font-weight:700;">🌐 ${{escapeHtml(f.value)}}</span> <span class="tag-badge" style="background:rgba(56,189,248,0.15); color:var(--accent); border:1px solid rgba(56,189,248,0.3);">In-Scope</span>`;
        }}

        const firstSrc = f.sources[0] || {{}};
        const fileName = (firstSrc.file || 'unknown').split('/').pop();
        const lineNum = firstSrc.line || 1;

        const tagBadges = f.tags.map(t => {{
          const cls = (t.includes('static') || t.includes('chunk')) ? 'tag-badge tag-static' : 'tag-badge';
          return `<span class="${{cls}}">${{escapeHtml(t)}}</span>`;
        }}).join('');

        tr.innerHTML = `
          <td style="font-family: var(--font-mono); font-weight: 500;">${{valueDisplay}}</td>
          <td><span class="conf-badge conf-${{f.confidence.toLowerCase()}}">${{f.confidence}}</span></td>
          <td><span style="font-size: 0.78rem; color:var(--text-muted);">${{escapeHtml(f.status)}}</span></td>
          <td>${{tagBadges}}</td>
          <td><span class="tag-badge">${{f.sources.length}} occ</span></td>
          <td>
            <span class="loc-badge" title="${{escapeHtml(firstSrc.file)}}">
              📄 ${{escapeHtml(fileName)}} : <span class="loc-line">L${{lineNum}}</span>
            </span>
          </td>
        `;
        tbody.appendChild(tr);
      }});
    }}

    function renderSourcesTable() {{
      const tbody = document.querySelector('#sourcesTable tbody');
      tbody.innerHTML = '';
      if (!sources.length) {{
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:20px;">No source records</td></tr>';
        return;
      }}
      sources.forEach(s => {{
        const sizeKb = (s.size_bytes / 1024).toFixed(1) + ' KB';
        const statusBadge = s.is_valid_js ? '<span class="conf-badge conf-high">Valid JS</span>' : '<span class="conf-badge conf-low">Invalid / Skipped</span>';
        const issues = [...(s.warnings || []), ...(s.errors || [])].join(', ') || 'None';

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:600; color:#93c5fd;">${{escapeHtml(s.identifier)}}</td>
          <td>${{sizeKb}}</td>
          <td>${{statusBadge}}</td>
          <td style="font-family:var(--font-mono); font-size:0.8rem;">${{escapeHtml(s.encoding || 'utf-8')}}</td>
          <td><small style="color:${{s.errors?.length ? 'var(--danger)' : 'var(--text-muted)'}};">${{escapeHtml(issues)}}</small></td>
        `;
        tbody.appendChild(tr);
      }});
    }}

    function renderRelationships() {{
      const container = document.getElementById('treeContainer');
      const hierarchy = relationships.host_hierarchy || {{}};
      const keys = Object.keys(hierarchy);
      if (!keys.length) {{
        container.innerHTML = '<p style="color:var(--text-muted);">No correlated endpoint hierarchy available.</p>';
        return;
      }}
      let html = '';
      keys.forEach(host => {{
        html += `<div style="margin-bottom:14px;"><span class="tree-host">🌐 ${{escapeHtml(host)}}</span><br>`;
        const endpoints = hierarchy[host] || [];
        endpoints.forEach(ep => {{
          html += `<div class="tree-ep">└── <span style="font-family:var(--font-mono);">${{escapeHtml(ep)}}</span></div>`;
        }});
        html += `</div>`;
      }});
      container.innerHTML = html;
    }}

    function openDrawer(f) {{
      activeFinding = f;
      document.getElementById('drawerTitle').textContent = f.normalizedValue || f.value;
      document.getElementById('drawerType').textContent = f.type + ' • ' + f.confidence + ' Confidence • ' + f.status;
      document.getElementById('drawerAssessment').textContent = f.assessment || 'No specific assessment';
      document.getElementById('drawerValue').textContent = f.value;
      document.getElementById('drawerProvenance').textContent = JSON.stringify(f.provenance, null, 2);
      
      document.getElementById('drawerSourceCount').textContent = f.sources.length;

      // Render prominent Leak Location Cards
      const leakCardsContainer = document.getElementById('drawerLeakCards');
      if (f.sources && f.sources.length > 0) {{
        leakCardsContainer.innerHTML = f.sources.map((s, idx) => `
          <div class="leak-card">
            <div class="leak-header">
              <span class="leak-file">📄 ${{escapeHtml(s.file)}}</span>
              <span class="leak-line-pill">Line ${{s.line}} : Col ${{s.column || 1}}</span>
            </div>
            ${{s.snippet ? `<div class="code-snippet"><span style="color:#64748b;">${{s.line}} |</span> ${{escapeHtml(s.snippet)}}</div>` : ''}}
          </div>
        `).join('');
      }} else {{
        leakCardsContainer.innerHTML = '<p style="color:var(--text-muted); font-size:0.85rem;">No source location recorded</p>';
      }}

      document.getElementById('drawerExtra').textContent = JSON.stringify(f.metadata || {{}}, null, 2);

      const revealBtn = document.getElementById('drawerRevealBtn');
      if (f.type === 'Secret' && f.metadata?.raw_secret) {{
        revealBtn.style.display = 'inline-block';
        revealBtn.textContent = 'Reveal Raw Secret';
      }} else {{
        revealBtn.style.display = 'none';
      }}

      document.getElementById('drawerOverlay').style.display = 'flex';
    }}

    function closeDrawer() {{
      document.getElementById('drawerOverlay').style.display = 'none';
      activeFinding = null;
    }}

    document.getElementById('drawerClose').onclick = closeDrawer;
    document.getElementById('drawerOverlay').onclick = (e) => {{
      if (e.target.id === 'drawerOverlay') closeDrawer();
    }};

    document.getElementById('drawerCopyBtn').onclick = () => {{
      if (activeFinding) {{
        const copyVal = activeFinding.normalizedValue || activeFinding.value;
        navigator.clipboard.writeText(copyVal).then(() => {{
          showToast('✓ Copied to clipboard!');
        }}).catch(() => {{
          showToast('✓ Copied to clipboard!');
        }});
      }}
    }};

    document.getElementById('drawerRevealBtn').onclick = () => {{
      if (activeFinding && activeFinding.metadata?.raw_secret) {{
        const valEl = document.getElementById('drawerValue');
        const raw = activeFinding.metadata.raw_secret;
        if (valEl.textContent === raw) {{
          valEl.textContent = activeFinding.value;
          document.getElementById('drawerRevealBtn').textContent = 'Reveal Raw Secret';
        }} else {{
          valEl.textContent = raw;
          document.getElementById('drawerRevealBtn').textContent = 'Mask Secret';
        }}
      }}
    }};

    function switchTab(tabName) {{
      document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
      const activeNav = document.querySelector(`.nav-item[data-tab="${{tabName}}"]`);
      if (activeNav) activeNav.classList.add('active');

      currentTab = tabName;
      document.getElementById('viewTitle').textContent = tabName === 'dashboard' ? 'Dashboard Overview' : tabName;

      document.getElementById('dashboardView').style.display = (tabName === 'dashboard') ? 'block' : 'none';
      document.getElementById('sourcesView').style.display = (tabName === 'sources') ? 'block' : 'none';
      document.getElementById('relationshipsView').style.display = (tabName === 'relationships') ? 'block' : 'none';
      document.getElementById('categoryView').style.display = (!['dashboard', 'sources', 'relationships'].includes(tabName)) ? 'block' : 'none';

      if (tabName === 'URL / Route' || tabName === 'API Endpoint') {{
        setAssetFilter('dynamic');
      }} else if (tabName === 'Subdomain / Host' || tabName === 'API Host') {{
        setHostFilter('all');
      }}

      if (tabName === 'dashboard') {{
        renderDashboard();
      }} else if (tabName === 'sources') {{
        renderSourcesTable();
      }} else if (tabName === 'relationships') {{
        renderRelationships();
      }} else {{
        renderCategoryTable();
      }}
    }}

    document.querySelectorAll('.nav-list .nav-item').forEach(item => {{
      item.onclick = () => {{
        switchTab(item.getAttribute('data-tab'));
      }};
    }});

    document.getElementById('globalSearch').oninput = (e) => {{
      searchQuery = e.target.value;
      if (currentTab === 'dashboard') {{
        renderDashboard();
      }} else if (currentTab === 'sources') {{
        renderSourcesTable();
      }} else if (currentTab !== 'relationships') {{
        renderCategoryTable();
      }}
    }};

    document.getElementById('filterConfidence').onchange = (e) => {{
      confidenceFilter = e.target.value;
      renderCategoryTable();
    }};

    document.getElementById('filterStatus').onchange = (e) => {{
      statusFilter = e.target.value;
      renderCategoryTable();
    }};

    function copyAllEndpoints() {{
      const eps = findings.filter(f => f.type === 'API Endpoint' && !f.isStaticAsset).map(f => f.normalizedValue || f.value);
      const unique = Array.from(new Set(eps.filter(Boolean)));
      if (!unique.length) {{
        showToast('No API endpoints to copy.');
        return;
      }}
      navigator.clipboard.writeText(unique.join('\\n')).then(() => {{
        showToast(`✓ Copied ${{unique.length}} endpoints to clipboard!`);
      }}).catch(() => {{
        showToast(`✓ Copied ${{unique.length}} endpoints to clipboard!`);
      }});
    }}

    function copyCurrentCategoryList() {{
      const currentFindings = getCurrentlyFilteredFindings();
      let items = [];

      if (currentTab === 'API Endpoint' || currentTab === 'URL / Route') {{
        items = currentFindings.map(f => f.normalizedValue || f.value);
      }} else if (currentTab === 'Parameter') {{
        items = currentFindings.map(f => f.normalizedValue || f.value);
      }} else if (currentTab === 'Subdomain / Host' || currentTab === 'API Host') {{
        items = currentFindings.map(f => f.normalizedValue || f.value);
      }} else if (currentTab === 'Static Resource') {{
        items = currentFindings.map(f => f.normalizedValue || f.value);
      }} else {{
        items = currentFindings.map(f => f.value);
      }}

      // Deduplicate items while preserving order
      const uniqueItems = Array.from(new Set(items.filter(Boolean)));

      if (!uniqueItems.length) {{
        showToast(`No items to copy for ${{currentTab}}.`);
        return;
      }}

      const textToCopy = uniqueItems.join('\\n');
      navigator.clipboard.writeText(textToCopy).then(() => {{
        showToast(`✓ Copied ${{uniqueItems.length}} items to clipboard!`);
      }}).catch(() => {{
        const textarea = document.createElement('textarea');
        textarea.value = textToCopy;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast(`✓ Copied ${{uniqueItems.length}} items to clipboard!`);
      }});
    }}

    function exportCategoryData() {{
      const items = getCurrentlyFilteredFindings();
      const blob = new Blob([JSON.stringify(items, null, 2)], {{ type: 'application/json' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${{currentTab.toLowerCase().replace(/\\s+/g, '_')}}_findings.json`;
      a.click();
    }}

    function escapeHtml(str) {{
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }}

    updateBadges();
    renderDashboard();
  </script>
</body>
</html>
"""
