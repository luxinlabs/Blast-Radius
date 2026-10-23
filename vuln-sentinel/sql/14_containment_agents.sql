-- Additive upgrade for the Blast Radius containment agent. Apply after 10 and 13.
CREATE TABLE IF NOT EXISTS VULN_SENTINEL_DB.SERVING.CONTAINMENT_ACTIONS (
  action_id VARCHAR PRIMARY KEY,
  client_id VARCHAR NOT NULL,
  emergency_id VARCHAR NOT NULL,
  revision VARCHAR NOT NULL,
  payload VARCHAR NOT NULL,
  status VARCHAR NOT NULL,
  requested_by VARCHAR NOT NULL,
  reviewer VARCHAR,
  reason VARCHAR,
  created_at VARCHAR NOT NULL,
  updated_at VARCHAR NOT NULL,
  action_type VARCHAR NOT NULL
);
GRANT SELECT,INSERT,UPDATE ON TABLE VULN_SENTINEL_DB.SERVING.CONTAINMENT_ACTIONS
TO ROLE VULN_SENTINEL_APP;
-- Transactions use the hybrid tracking lock from migration 10.
-- APPLIED means a policy is active in `sentinel gate`. CI must call the gate and require exit 0.
-- No infrastructure, WAF, alerting or host-isolation permissions are granted here.
