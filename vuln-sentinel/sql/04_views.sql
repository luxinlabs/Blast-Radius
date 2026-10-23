create or replace view VULN_SENTINEL_DB.SERVING.V_BLAST_RADIUS(
	ECOSYSTEM,
	COMPROMISED,
	DEPENDENT,
	HOPS,
	SHORTEST_PATH,
	RUNS_WHERE,
	HANDLES_SECRETS,
	SECRET_TYPES
) COMMENT='For each package, every watchlist package that depends on it (directly or transitively) via required runtime deps'
 as
WITH RECURSIVE e AS (
  SELECT DISTINCT ecosystem, LOWER(parent) parent, LOWER(child) child FROM VULN_SENTINEL_DB.CORE.DEPENDENCIES WHERE dep_kind IN ('runtime','peer')
), walk (ecosystem, compromised, dependent, path, hops) AS (
  SELECT ecosystem, child, parent, parent||' -> '||child, 1 FROM e
  UNION ALL
  SELECT w.ecosystem, w.compromised, e.parent, e.parent||' -> '||w.path, w.hops+1
  FROM walk w JOIN e ON e.ecosystem=w.ecosystem AND e.child=w.dependent
  WHERE w.hops < 6 AND POSITION(' '||e.parent||' ' IN ' '||REPLACE(w.path,' -> ','  ')||' ')=0
)
SELECT k.ecosystem, k.compromised, k.dependent, MIN(k.hops) hops, MIN_BY(k.path,k.hops) shortest_path,
       wl.runs_where, wl.handles_secrets, wl.secret_types
FROM walk k JOIN VULN_SENTINEL_DB.CORE.WATCHLIST wl ON wl.ecosystem=k.ecosystem AND wl.name=k.dependent
GROUP BY ALL;

create or replace view VULN_SENTINEL_DB.SERVING.V_PACKAGE_RISK(
	ECOSYSTEM,
	NAME,
	LATEST_VERSION,
	MONTHLY_DOWNLOADS,
	RUNS_WHERE,
	HANDLES_SECRETS,
	OPEN_ADVISORIES_ANY_VERSION,
	MALICIOUS_VERSIONS,
	MALICIOUS_VERSION_LIST,
	ADVISORIES_ON_LATEST,
	MAX_SEV_RANK
) as
SELECT w.ecosystem, w.name, p.latest_version, p.monthly_downloads, w.runs_where, w.handles_secrets,
  COUNT(DISTINCT r.advisory_id) open_advisories_any_version,
  COUNT(DISTINCT IFF(r.incident_type='MALICIOUS_RELEASE', r.version, NULL)) malicious_versions,
  ARRAY_AGG(DISTINCT IFF(r.incident_type='MALICIOUS_RELEASE', r.version, NULL)) malicious_version_list,
  COUNT(DISTINCT IFF(r.version=p.latest_version, r.advisory_id, NULL)) advisories_on_latest,
  MAX(CASE r.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MODERATE' THEN 2 WHEN 'LOW' THEN 1 END) max_sev_rank
FROM VULN_SENTINEL_DB.CORE.WATCHLIST w
LEFT JOIN VULN_SENTINEL_DB.CORE.PACKAGES p ON p.ecosystem=w.ecosystem AND LOWER(p.name)=w.name
LEFT JOIN VULN_SENTINEL_DB.SERVING.PACKAGE_VERSION_RISK r ON r.ecosystem=w.ecosystem AND r.name=w.name
GROUP BY ALL;
