-- Host the API and dashboard in Snowpark Container Services. Run as a role that can create compute pools.
-- Build and push first (from vuln-sentinel/), using the registry URL that SHOW IMAGE REPOSITORIES prints:
--   docker build --platform linux/amd64 -t <registry>/vuln_sentinel_db/serving/images/vuln-sentinel:latest .
--   docker push <registry>/vuln_sentinel_db/serving/images/vuln-sentinel:latest
CREATE IMAGE REPOSITORY IF NOT EXISTS VULN_SENTINEL_DB.SERVING.IMAGES;
SHOW IMAGE REPOSITORIES IN SCHEMA VULN_SENTINEL_DB.SERVING;

CREATE COMPUTE POOL IF NOT EXISTS VULN_SENTINEL_POOL MIN_NODES = 1 MAX_NODES = 1 INSTANCE_FAMILY = CPU_X64_XS;

-- Mint fresh tokens for this deployment; do not reuse the local demo tokens. JSON shape: see .env.example.
CREATE SECRET IF NOT EXISTS VULN_SENTINEL_DB.SERVING.SENTINEL_TOKENS
  TYPE = GENERIC_STRING SECRET_STRING = '<SENTINEL_TOKENS json>';

CREATE STAGE IF NOT EXISTS VULN_SENTINEL_DB.SERVING.SPECS;
-- PUT file://snowflake/service.yaml @VULN_SENTINEL_DB.SERVING.SPECS AUTO_COMPRESS=FALSE OVERWRITE=TRUE;

CREATE SERVICE IF NOT EXISTS VULN_SENTINEL_DB.SERVING.VULN_SENTINEL
  IN COMPUTE POOL VULN_SENTINEL_POOL
  FROM @VULN_SENTINEL_DB.SERVING.SPECS SPECIFICATION_FILE = 'service.yaml';

SHOW ENDPOINTS IN SERVICE VULN_SENTINEL_DB.SERVING.VULN_SENTINEL;
-- Set SENTINEL_ALLOWED_HOSTS / SENTINEL_ALLOWED_ORIGINS in service.yaml to the api endpoint's ingress_url,
-- then ALTER SERVICE ... FROM SPECIFICATION_FILE to apply it (MCP rejects unknown hosts).
