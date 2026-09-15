"""Technology and frontend library fingerprinting analyzer for JSXRay."""

import re
from typing import Dict, List, Optional, Tuple
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class TechSignature:
    def __init__(
        self,
        name: str,
        category: str,
        indicators: List[re.Pattern],
        version_pattern: Optional[re.Pattern] = None,
    ) -> None:
        self.name = name
        self.category = category
        self.indicators = indicators
        self.version_pattern = version_pattern


TECH_SIGNATURES: List[TechSignature] = [
    TechSignature(
        "Svelte",
        "Frontend Framework",
        [re.compile(r"__svelte__|svelte/internal|create_ssr_component|SvelteComponent|SvelteElement|\.svelte\b")],
        re.compile(r'svelte@([0-9\.]+)'),
    ),
    TechSignature(
        "SvelteKit",
        "Meta Framework",
        [re.compile(r"@sveltejs/kit|__sveltekit|__SVELTEKIT__")],
        re.compile(r'@sveltejs/kit@([0-9\.]+)'),
    ),
    TechSignature(
        "Vite",
        "Bundler",
        [re.compile(r"import\.meta\.env|import\.meta\.hot|__vite__plugin__|/@vite/client|__vite__")],
        None,
    ),
    TechSignature(
        "React",
        "Frontend Framework",
        [re.compile(r"React\.createElement|__REACT_DEVTOOLS_GLOBAL_HOOK__|react\.production\.min\.js|react-dom|react/jsx-runtime|jsx-runtime|_jsx\b|_jsxs\b")],
        re.compile(r'React\s*=\s*\{[^\}]*version:\s*["\']([0-9\.]+)["\']|react@([0-9\.]+)'),
    ),
    TechSignature(
        "Next.js",
        "Meta Framework",
        [re.compile(r"__NEXT_DATA__|/_next/static/|next/dist/client|next/router|next/navigation")],
        re.compile(r'next@([0-9\.]+)|"NEXT_VERSION":"([0-9\.]+)"'),
    ),
    TechSignature(
        "Vue.js",
        "Frontend Framework",
        [re.compile(r"Vue\.prototype|__VUE__|createApp\s*\(|vue\.runtime|vue\.min\.js|@vue/reactivity|@vue/runtime")],
        re.compile(r'Vue\.version\s*=\s*["\']([0-9\.]+)["\']|vue@([0-9\.]+)'),
    ),
    TechSignature(
        "Angular",
        "Frontend Framework",
        [re.compile(r"ng-version|@angular/core|ngForm|angular\.module|@angular/common")],
        re.compile(r'ng-version=["\']([0-9\.]+)["\']|@angular/core@([0-9\.]+)'),
    ),
    TechSignature(
        "GraphQL",
        "Query Language / API",
        [re.compile(r"\bgql`|ApolloClient|useQuery\s*\(|useMutation\s*\(|__typename|graphql-tag")],
        None,
    ),
    TechSignature(
        "Socket.IO",
        "Real-Time / WebSocket",
        [re.compile(r"socket\.io-client|io\.connect\s*\(|\bio\s*\(\s*['\"]https?://")],
        re.compile(r'socket\.io-client@([0-9\.]+)'),
    ),
    TechSignature(
        "Tailwind CSS",
        "CSS Framework",
        [re.compile(r"tailwindcss|@tailwindcss|tailwind\.config")],
        None,
    ),
    TechSignature(
        "Axios",
        "HTTP Client",
        [re.compile(r"axios\.create|axios\.interceptors|axios\.defaults|axios\.get\s*\(|axios\.post\s*\(")],
        re.compile(r'axios@([0-9\.]+)|axios\/([0-9\.]+)'),
    ),
    TechSignature(
        "jQuery",
        "DOM Library",
        [re.compile(r"jQuery\.fn\.jquery|jQuery\.ajaxSetup|window\.jQuery|window\.\$")],
        re.compile(r'jQuery\.fn\.jquery\s*=\s*["\']([0-9\.]+)["\']|jquery@([0-9\.]+)'),
    ),
    TechSignature(
        "Webpack",
        "Bundler",
        [re.compile(r"webpackChunk|__webpack_require__|webpackJsonp|webpack/runtime")],
        None,
    ),
    TechSignature(
        "Redux",
        "State Management",
        [re.compile(r"createStore|applyMiddleware|combineReducers|@@redux/INIT|@reduxjs/toolkit")],
        re.compile(r'redux@([0-9\.]+)'),
    ),
    TechSignature(
        "Lodash",
        "Utility Library",
        [re.compile(r"lodash\.debounce|lodash\.cloneDeep|_\.isObject|lodash\.min\.js|lodash/debounce")],
        re.compile(r'VERSION\s*=\s*["\']([0-9\.]+)["\']|lodash@([0-9\.]+)'),
    ),
    TechSignature(
        "Bootstrap",
        "CSS/UI Framework",
        [re.compile(r"bootstrap\.min\.js|bootstrap\.Modal|bootstrap\.Dropdown")],
        re.compile(r'bootstrap@([0-9\.]+)|VERSION\s*=\s*["\']([0-9\.]+)["\']'),
    ),
]


class TechnologyAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "technologies"

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        code = source.effective_code
        lines = code.splitlines()

        for tech in TECH_SIGNATURES:
            for ind in tech.indicators:
                match = ind.search(code)
                if match:
                    version = None
                    if tech.version_pattern:
                        v_match = tech.version_pattern.search(code)
                        if v_match:
                            version = v_match.group(1) or v_match.group(2)

                    # Find line number of the indicator match
                    match_pos = match.start()
                    line_num = code[:match_pos].count("\n") + 1
                    snippet = lines[line_num - 1].strip()[:200] if line_num - 1 < len(lines) else match.group(0)

                    display_val = f"{tech.name} {version}" if version else tech.name

                    findings.append(
                        Finding(
                            type=FindingType.TECHNOLOGY,
                            value=display_val,
                            normalized_value=tech.name,
                            confidence=Confidence.HIGH,
                            status=FindingStatus.DETECTED,
                            source_file=source.file_path,
                            source_url=source.url,
                            line=line_num,
                            column=1,
                            snippet=snippet,
                            original_source=match.group(0),
                            reconstructed_source=display_val,
                            discovery_method="AST analysis",
                            tags=["technology", tech.category.lower().replace(" ", "-"), tech.name.lower()],
                            extra_data={
                                "technology": tech.name,
                                "category": tech.category,
                                "version": version,
                                "indicator": match.group(0),
                            },
                        )
                    )
                    break

        return findings
