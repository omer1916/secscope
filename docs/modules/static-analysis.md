# Static analysis modules (M3)

All four modules need the project source (folder or archive) and never execute it.

## `sast` — static code analysis

**Does:** native pattern rules for JavaScript/TypeScript, PHP and templates
(`rules/native/*.yaml`); Python AST checks with function-local taint tracking (request data →
SQL / shell / eval / file paths / redirects / outgoing requests / HTML responses), framework
misconfiguration (debug mode, CORS, CSRF, cookie flags, static root), weak crypto, insecure
randomness, hardcoded secrets, error leaks, code quality (swallowed exceptions, debug code).
Optionally Semgrep (our own taint rules in `rules/semgrep/`) and Bandit (mapped through
`rules/tool_map.yaml`). Without Semgrep the module states *reduced coverage*.

**Does not:** inter-procedural / cross-file taint (a value passed through two functions in
different files is not followed by the native engine; Semgrep taint mode covers some of it),
languages other than Python/JS/TS/PHP, business-logic flaws, authorization (IDOR needs DAST).

**False-positive sources:** dynamic SQL built from trusted constants (reported with medium
confidence); `innerHTML` with server-trusted HTML; sanitisers unknown to us (extend
`SANITIZERS` in `python_checks.py`). Suppress per line with `# secscope: ignore RULE-ID`.

## `secrets` — secret scanning

**Does:** known token formats (cloud, SaaS, private keys, JWTs, connection URLs), high-entropy
values assigned to secret-like names, committed `.env` files; gitleaks for the working tree and
the **git history** (`SECRET-HISTORY-001`). Values are masked before they reach any event,
log, database row or report.

**Does not:** verify whether a key is live (no outbound calls).

**False-positive sources:** example values in docs/tests (lower confidence under
`test/`, `docs/`, `examples/`), random-looking non-secrets (entropy ≥ 3.0 needed).

## `sca` — dependencies

**Does:** inventory from package-lock/npm-shrinkwrap, requirements*.txt (pinned), Pipfile.lock,
poetry.lock, composer.lock; CycloneDX 1.5 SBOM (`work/<scan>/sbom.cdx.json`); vulnerabilities
via Trivy and osv-scanner **offline**, merged per package (one finding per vulnerable package
version with all advisories and the minimal fixed version); typosquatting suspicion; install
scripts; copyleft licences.

**Does not:** reachability analysis; unpinned requirements (`flask>=2`) cannot be matched to a
version and are listed as unpinned; online services (`npm audit`, `pip-audit`) are not used
(ADR-006).

## `config_audit` — configuration / infrastructure

**Does:** Dockerfile (root user, unpinned base image, `ADD <url>`, secrets in ENV/ARG),
docker-compose (privileged, host network, docker.sock, ports on all interfaces), nginx
(autoindex, server_tokens, missing headers), `.htaccess` (Indexes), GitHub Actions
(`pull_request_target` with PR checkout, expression injection in `run:`), source maps in public
folders, backup files, secret files not covered by `.gitignore`.

**Does not:** Kubernetes/Terraform (Trivy `config` can be added later).
