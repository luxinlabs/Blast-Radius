-- Malicious release: litellm 1.107.0 (MAL-2026-2144), with an AI-written SRE brief
CALL VULN_SENTINEL_DB.SERVING.RESPOND('pypi', 'litellm', '1.107.0', TRUE);

-- Malicious releases from the September 2025 maintainer-phish hijack and the axios incident
CALL VULN_SENTINEL_DB.SERVING.RESPOND('npm', 'chalk', '5.6.1', FALSE);
CALL VULN_SENTINEL_DB.SERVING.RESPOND('npm', 'axios', '1.14.1', FALSE);

-- Known CVEs: Next.js middleware auth bypass (CVE-2025-29927) and later advisories
CALL VULN_SENTINEL_DB.SERVING.RESPOND('npm', 'next', '15.2.2', FALSE)
  ->> SELECT $1:incident_type, $1:advisory_count, $1:recommended_version FROM $1;

-- Who is affected if urllib3 is compromised?
SELECT * FROM VULN_SENTINEL_DB.SERVING.V_BLAST_RADIUS WHERE compromised = 'urllib3' ORDER BY hops;

-- Watchlist overview
SELECT * FROM VULN_SENTINEL_DB.SERVING.V_PACKAGE_RISK ORDER BY malicious_versions DESC, open_advisories_any_version DESC;
