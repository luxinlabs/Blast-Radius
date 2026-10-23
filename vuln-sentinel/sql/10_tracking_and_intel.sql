-- Existing deployment: run 10, 11, then 12. Never rerun file 01 on a populated database.
-- The enforced hybrid lock serializes tracking mutations across the API and native task.
CREATE HYBRID TABLE IF NOT EXISTS VULN_SENTINEL_DB.SERVING.TRACKING_LOCK (
  lock_id INTEGER PRIMARY KEY, generation INTEGER NOT NULL
);
MERGE INTO VULN_SENTINEL_DB.SERVING.TRACKING_LOCK t USING (SELECT 1 lock_id) s
ON t.lock_id=s.lock_id WHEN NOT MATCHED THEN INSERT (lock_id,generation) VALUES (1,0);

CREATE TABLE IF NOT EXISTS VULN_SENTINEL_DB.SERVING.CLIENTS (
  client_id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, created_at VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS VULN_SENTINEL_DB.SERVING.CLIENT_SBOM (
  client_id VARCHAR NOT NULL, revision VARCHAR NOT NULL, payload VARCHAR NOT NULL, created_at VARCHAR NOT NULL, PRIMARY KEY(client_id, revision)
);

CREATE TABLE IF NOT EXISTS VULN_SENTINEL_DB.SERVING.EMERGENCIES (
  emergency_id VARCHAR PRIMARY KEY, client_id VARCHAR NOT NULL, revision VARCHAR NOT NULL, fingerprint VARCHAR NOT NULL, status VARCHAR NOT NULL, payload VARCHAR NOT NULL, proposal VARCHAR, reviewer VARCHAR, reason VARCHAR, created_at VARCHAR NOT NULL, updated_at VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS VULN_SENTINEL_DB.SERVING.AGENT_EVENTS (
  event_id VARCHAR PRIMARY KEY, client_id VARCHAR NOT NULL, actor VARCHAR NOT NULL, kind VARCHAR NOT NULL, payload VARCHAR NOT NULL, created_at VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS VULN_SENTINEL_DB.INTEL.SIGNAL_FEED (
  kind VARCHAR NOT NULL, indicator VARCHAR NOT NULL, score FLOAT, source VARCHAR NOT NULL,
  observed_at TIMESTAMP_TZ NOT NULL, expires_at TIMESTAMP_TZ
);

-- Map licensed provider data into this schema after accepting its terms separately.
-- Supported kinds: kev, exploit, ip, domain, tor, ai_endpoint; scores normalized to [0,1].
CREATE OR REPLACE VIEW VULN_SENTINEL_DB.SERVING.V_PACKAGE_RISK_ENRICHED AS
WITH cves AS (
  SELECT DISTINCT r.ecosystem,r.name,f.value::VARCHAR cve
  FROM VULN_SENTINEL_DB.SERVING.PACKAGE_VERSION_RISK r,
       LATERAL FLATTEN(input=>r.cve_ids) f
), signals AS (
  SELECT c.ecosystem,c.name,
         MAX(IFF(i.kind='kev',1,0))=1 known_exploited,
         MAX(IFF(i.kind='exploit' AND i.score BETWEEN 0 AND 1,i.score,NULL)) exploit_score
  FROM cves c JOIN VULN_SENTINEL_DB.INTEL.SIGNAL_FEED i ON i.indicator=c.cve
  WHERE i.expires_at IS NULL OR i.expires_at>CURRENT_TIMESTAMP()
  GROUP BY c.ecosystem,c.name
)
SELECT r.*,COALESCE(s.known_exploited,FALSE) known_exploited,s.exploit_score
FROM VULN_SENTINEL_DB.SERVING.V_PACKAGE_RISK r
LEFT JOIN signals s ON r.ecosystem=s.ecosystem AND r.name=s.name;

CREATE STAGE IF NOT EXISTS VULN_SENTINEL_DB.SERVING.APP_CODE;
