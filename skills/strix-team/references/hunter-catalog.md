# Hunter catalog

Maps vulnerability classes to the knowledge packs a hunter should read. Pack names are paths relative to the skills root (`strix/skills/`, resolved by the resolver in the agent files). Give each hunter at most 5 packs. Always add `analysis/counterevidence` to validators; hunters already load it by default.

| Vulnerability class | Packs |
|---|---|
| Access control: IDOR / BOLA | vulnerabilities/idor, vulnerabilities/broken_function_level_authorization, vulnerabilities/mass_assignment |
| Function-level authorization, privilege escalation | vulnerabilities/broken_function_level_authorization, vulnerabilities/idor, vulnerabilities/business_logic |
| Authentication, JWT, sessions | vulnerabilities/authentication_jwt, vulnerabilities/weak_password_detection, protocols/oauth |
| OAuth / SSO flows | protocols/oauth, vulnerabilities/authentication_jwt, vulnerabilities/open_redirect, vulnerabilities/csrf |
| SQL injection | vulnerabilities/sql_injection, tooling/sqlmap, vulnerabilities/query_language_injection |
| NoSQL / query-language injection | vulnerabilities/nosql_injection, vulnerabilities/query_language_injection |
| XSS, DOM and client-side | vulnerabilities/xss, vulnerabilities/browser_security, vulnerabilities/prototype_pollution |
| CSRF, header injection | vulnerabilities/csrf, vulnerabilities/header_injection, vulnerabilities/browser_security |
| SSRF | vulnerabilities/ssrf, vulnerabilities/open_redirect, cloud/aws |
| Remote code execution, command and argument injection | vulnerabilities/rce, vulnerabilities/argument_injection, vulnerabilities/ssti |
| Template injection | vulnerabilities/ssti, vulnerabilities/rce |
| Deserialization | vulnerabilities/insecure_deserialization, vulnerabilities/rce |
| File upload | vulnerabilities/insecure_file_uploads, vulnerabilities/path_traversal_lfi_rfi, vulnerabilities/xxe |
| Path traversal, LFI/RFI | vulnerabilities/path_traversal_lfi_rfi, vulnerabilities/insecure_file_uploads |
| XXE / XML parsing | vulnerabilities/xxe, vulnerabilities/ssrf |
| Information disclosure, secrets | vulnerabilities/information_disclosure, custom/source_aware_sast, tooling/nuclei |
| Business logic and race conditions | vulnerabilities/business_logic, vulnerabilities/race_conditions, vulnerabilities/semantic_confusion |
| HTTP request smuggling | vulnerabilities/http_request_smuggling, vulnerabilities/header_injection |
| Open redirect | vulnerabilities/open_redirect, vulnerabilities/csrf |
| Subdomain takeover | vulnerabilities/subdomain_takeover, reconnaissance/asset_discovery |
| GraphQL | protocols/graphql, vulnerabilities/broken_function_level_authorization, vulnerabilities/idor |
| API spec driven testing | custom/api_spec_testing, vulnerabilities/idor, vulnerabilities/mass_assignment |
| LLM / agentic features | vulnerabilities/llm_prompt_injection, vulnerabilities/agentic_system_security, technologies/llm_applications |
| Dependency CVEs, supply chain | custom/dependency_cve_scanning, custom/npx_confusion |
| Cloud and Kubernetes misconfiguration | cloud/aws, cloud/azure, cloud/gcp, cloud/kubernetes (pick the one that matches) |

## Technology add-ons

Add one pack when the stack is known, replacing the least relevant class pack to stay within 5:

| Stack | Pack |
|---|---|
| Django | frameworks/django |
| FastAPI | frameworks/fastapi |
| NestJS | frameworks/nestjs |
| Next.js | frameworks/nextjs |
| Firebase | technologies/firebase |
| Supabase | technologies/supabase |
| Auth0 | technologies/auth0 |
| Electron | technologies/electron_desktop_apps |
| Active Directory | technologies/active_directory |
| Grafana / Prometheus | technologies/grafana_prometheus |

## Always-available method packs

| Need | Pack |
|---|---|
| Closing a candidate (every hunter and validator) | analysis/counterevidence |
| Rating severity | analysis/severity_calibration |
| Writing a fix | analysis/fix_verification |
| Reading source for sinks | analysis/source_aware_discovery |
| Mode behavior | scan_modes/quick, scan_modes/standard, scan_modes/deep |

## Tooling packs (recon, SAST, validators)

tooling/nmap, tooling/httpx, tooling/subfinder, tooling/ffuf, tooling/katana, tooling/nuclei, tooling/naabu, tooling/hurl, tooling/opengrep, tooling/python, tooling/hypothesis, tooling/agent_browser, reconnaissance/asset_discovery, reconnaissance/infrastructure_lifecycle, coordination/source_aware_whitebox.

## Splitting rule

One hunter = one class cluster (a row above) x one component or surface. Do not give a hunter the whole app. For a class with many surfaces (for example IDOR on 40 endpoints) split by component, not by endpoint.
