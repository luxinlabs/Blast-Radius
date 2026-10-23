-- Seed data: the watchlist and the response playbook.

INSERT OVERWRITE INTO VULN_SENTINEL_DB.CORE.WATCHLIST (ECOSYSTEM, NAME, RUNS_WHERE, IS_MOSTLY_TRANSITIVE, HANDLES_SECRETS, SECRET_TYPES, DEMO_REASON)
SELECT 'npm', 'axios', 'frontend+backend', FALSE, TRUE, ARRAY_CONSTRUCT('auth headers', 'api tokens'), 'Most-installed HTTP client; blast radius spans browser bundles and servers'
UNION ALL SELECT 'npm', 'express', 'backend', FALSE, FALSE, ARRAY_CONSTRUCT(), 'Default Node server; middleware on every request path'
UNION ALL SELECT 'npm', 'next', 'frontend+ssr', FALSE, TRUE, ARRAY_CONSTRUCT('server env vars', 'session cookies'), 'Middleware auth bypass precedent; customer-facing sites'
UNION ALL SELECT 'npm', 'react', 'frontend+ssr', FALSE, FALSE, ARRAY_CONSTRUCT(), 'Server Components RCE precedent'
UNION ALL SELECT 'npm', 'react-dom', 'frontend+ssr', FALSE, FALSE, ARRAY_CONSTRUCT(), 'Server rendering path for React'
UNION ALL SELECT 'npm', 'lodash', 'everywhere', TRUE, FALSE, ARRAY_CONSTRUCT(), 'Repeated prototype-pollution CVEs; buried in dependency trees'
UNION ALL SELECT 'npm', 'debug', 'everywhere', TRUE, FALSE, ARRAY_CONSTRUCT(), 'Sep 2025 maintainer-phish hijack target; mostly transitive'
UNION ALL SELECT 'npm', 'chalk', 'everywhere', TRUE, FALSE, ARRAY_CONSTRUCT(), 'Sep 2025 maintainer-phish hijack target; mostly transitive'
UNION ALL SELECT 'npm', 'ansi-styles', 'everywhere', TRUE, FALSE, ARRAY_CONSTRUCT(), 'Sep 2025 maintainer-phish hijack target; mostly transitive'
UNION ALL SELECT 'npm', 'jsonwebtoken', 'backend', FALSE, TRUE, ARRAY_CONSTRUCT('jwt signing keys'), 'Signature-verification CVEs mean login auth bypass'
UNION ALL SELECT 'npm', 'ua-parser-js', 'frontend+backend', FALSE, FALSE, ARRAY_CONSTRUCT(), '2021 account hijack shipped a miner and stealer'
UNION ALL SELECT 'PyPI', 'requests', 'backend', FALSE, TRUE, ARRAY_CONSTRUCT('auth headers', 'api tokens'), 'Effectively universal Python HTTP client'
UNION ALL SELECT 'PyPI', 'urllib3', 'backend', TRUE, TRUE, ARRAY_CONSTRUCT('auth headers'), 'Transitive under requests, boto3/botocore and more'
UNION ALL SELECT 'PyPI', 'certifi', 'backend', TRUE, FALSE, ARRAY_CONSTRUCT(), 'Holds the CA trust bundle used by requests'
UNION ALL SELECT 'PyPI', 'cryptography', 'backend', FALSE, TRUE, ARRAY_CONSTRUCT('private keys', 'tls'), 'Bundles OpenSSL; OpenSSL CVEs flow through it'
UNION ALL SELECT 'PyPI', 'django', 'backend', FALSE, TRUE, ARRAY_CONSTRUCT('SECRET_KEY', 'db creds'), 'Request-path framework with regular CVEs'
UNION ALL SELECT 'PyPI', 'flask', 'backend', FALSE, TRUE, ARRAY_CONSTRUCT('SECRET_KEY'), 'Request-path framework'
UNION ALL SELECT 'PyPI', 'fastapi', 'backend', FALSE, FALSE, ARRAY_CONSTRUCT(), 'Request-path framework built on starlette'
UNION ALL SELECT 'PyPI', 'starlette', 'backend', TRUE, FALSE, ARRAY_CONSTRUCT(), 'Multipart-parsing DoS history'
UNION ALL SELECT 'PyPI', 'python-multipart', 'backend', TRUE, FALSE, ARRAY_CONSTRUCT(), 'Multipart-parsing DoS history'
UNION ALL SELECT 'PyPI', 'jinja2', 'backend', TRUE, FALSE, ARRAY_CONSTRUCT(), 'Sandbox-escape history'
UNION ALL SELECT 'PyPI', 'pyyaml', 'backend', TRUE, FALSE, ARRAY_CONSTRUCT(), 'Unsafe-load history'
UNION ALL SELECT 'PyPI', 'boto3', 'backend', FALSE, TRUE, ARRAY_CONSTRUCT('aws credentials'), 'Runs with cloud credentials in memory'
UNION ALL SELECT 'PyPI', 'botocore', 'backend', TRUE, TRUE, ARRAY_CONSTRUCT('aws credentials'), 'Runs with cloud credentials in memory'
UNION ALL SELECT 'PyPI', 'litellm', 'backend', FALSE, TRUE, ARRAY_CONSTRUCT('llm provider api keys'), 'AI gateway holding LLM keys; recent compromise report';

INSERT OVERWRITE INTO VULN_SENTINEL_DB.SERVING.RESPONSE_PLAYBOOK (INCIDENT_TYPE, STEP_NO, PHASE, ACTION, APPLIES_WHEN, OWNER, AUTOMATABLE) VALUES
('MALICIOUS_RELEASE', 1, 'CONTAIN', 'Freeze deploys and CI for affected services; block the bad version in the registry proxy/firewall (Artifactory, Nexus, pip/npm config)', 'always', 'SRE', TRUE),
('MALICIOUS_RELEASE', 2, 'CONTAIN', 'Pin to the recommended safe version in manifest + lockfile; regenerate lockfile with --frozen/--require-hashes', 'always', 'agent', TRUE),
('MALICIOUS_RELEASE', 3, 'ERADICATE', 'Purge package caches (~/.npm, node_modules, pip cache, wheelhouse, Docker layers) and rebuild images from clean base', 'always', 'agent', TRUE),
('MALICIOUS_RELEASE', 4, 'ERADICATE', 'Treat every host/CI runner that installed the version as compromised: re-image, do not just uninstall', 'always', 'SRE', FALSE),
('MALICIOUS_RELEASE', 5, 'RECOVER', 'Rotate all secrets reachable from affected hosts, from a clean machine', 'handles_secrets', 'SRE', FALSE),
('MALICIOUS_RELEASE', 6, 'INVESTIGATE', 'Hunt IOCs in egress/DNS/auth logs for the install window (from first publish of bad version until pin); check for new persistence files', 'always', 'agent', TRUE),
('MALICIOUS_RELEASE', 7, 'INVESTIGATE', 'Check egress to AI/LLM endpoints and anonymizers (Edg3 egress + Tor lists) from affected hosts', 'handles_secrets', 'agent', TRUE),
('MALICIOUS_RELEASE', 8, 'COMMUNICATE', 'Notify downstream consumers in blast radius; file incident record with timeline', 'always', 'human', FALSE),
('VULNERABILITY', 1, 'ASSESS', 'Confirm installed version is in affected range and the vulnerable code path is reachable (feature/config used?)', 'always', 'agent', TRUE),
('VULNERABILITY', 2, 'ASSESS', 'Prioritise: CRITICAL/HIGH, exploited-in-the-wild (CISA KEV / DVE score), internet-facing tier first', 'always', 'agent', TRUE),
('VULNERABILITY', 3, 'REMEDIATE', 'Upgrade to the lowest fixed version on the current major; open PR with tests', 'fix_available', 'agent', TRUE),
('VULNERABILITY', 4, 'MITIGATE', 'No fix yet: apply compensating control (WAF rule, header strip, disable feature flag, input limits)', 'no_fix', 'SRE', FALSE),
('VULNERABILITY', 5, 'VERIFY', 'Re-scan lockfile, run test suite, replay sanitized production requests in staging', 'always', 'agent', TRUE),
('VULNERABILITY', 6, 'APPROVE', 'Human reviews diff, reachability evidence and rollback plan before merge', 'always', 'human', FALSE),
('UNAVAILABLE', 1, 'CONTAIN', 'Package/version unpublished or yanked: pin to last good published version', 'always', 'agent', TRUE),
('UNAVAILABLE', 2, 'RECOVER', 'Serve from internal mirror/vendor directory; enable registry proxy caching', 'always', 'SRE', FALSE),
('UNAVAILABLE', 3, 'ASSESS', 'If yanked for security reasons, escalate to MALICIOUS_RELEASE or VULNERABILITY playbook', 'always', 'agent', TRUE),
('TRUST_STORE', 1, 'ASSESS', 'CA bundle change (e.g. certifi): diff added/removed roots vs current bundle', 'always', 'agent', TRUE),
('TRUST_STORE', 2, 'REMEDIATE', 'Upgrade certifi or OS trust store; check services pinning certificates or using custom bundles', 'always', 'agent', TRUE),
('TRUST_STORE', 3, 'VERIFY', 'Run TLS handshake checks against all outbound dependencies before rollout', 'always', 'SRE', TRUE);
