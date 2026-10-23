create or replace task VULN_SENTINEL_DB.SERVING.TASK_REFRESH_ADVISORIES
	warehouse=DEFAULT_WH
	schedule='USING CRON 7 * * * * UTC'
	COMMENT='Hourly OSV reload for npm+PyPI and risk rebuild'
	as CALL VULN_SENTINEL_DB.SERVING.REFRESH('ADVISORIES');

create or replace task VULN_SENTINEL_DB.SERVING.TASK_REFRESH_FULL
	warehouse=DEFAULT_WH
	schedule='USING CRON 30 4 * * * UTC'
	COMMENT='Daily registry, dependency graph, OSV and risk refresh'
	as CALL VULN_SENTINEL_DB.SERVING.REFRESH('FULL');
