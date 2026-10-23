-- Outbound access for OSV, npm and PyPI. Requires CREATE INTEGRATION on the account.
-- Run after 01 (needs the RAW schema), before 03 (procedures reference the integration).
CREATE OR REPLACE NETWORK RULE VULN_SENTINEL_DB.RAW.PUBLIC_SOURCES_RULE
  MODE = EGRESS
  TYPE = HOST_PORT
  VALUE_LIST = ('osv-vulnerabilities.storage.googleapis.com', 'registry.npmjs.org', 'api.npmjs.org',
                'pypi.org', 'hugovk.github.io', 'hugovk.dev');

CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION BLAST_RADIUS_PUBLIC_EAI
  ALLOWED_NETWORK_RULES = (VULN_SENTINEL_DB.RAW.PUBLIC_SOURCES_RULE)
  ENABLED = TRUE
  COMMENT = 'Blast-Radius: OSV, npm, PyPI';
