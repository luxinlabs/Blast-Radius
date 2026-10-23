-- First full load. Takes several minutes (downloads the OSV exports and registry metadata).
CALL VULN_SENTINEL_DB.SERVING.REFRESH('FULL');

-- Optional: turn on the schedules (hourly advisories, daily full refresh). They consume warehouse credits.
-- ALTER TASK VULN_SENTINEL_DB.SERVING.TASK_REFRESH_ADVISORIES RESUME;
-- ALTER TASK VULN_SENTINEL_DB.SERVING.TASK_REFRESH_FULL RESUME;
