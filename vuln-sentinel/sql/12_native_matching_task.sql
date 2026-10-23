-- Build dist/vuln_sentinel.zip with scripts/package_snowflake.py and upload it to APP_CODE.
-- From a Snowflake Git repository, copy the tracked archive (replace YOUR_REPO):
-- COPY FILES INTO @VULN_SENTINEL_DB.SERVING.APP_CODE
--   FROM @YOUR_REPO/branches/main/vuln-sentinel/dist/ FILES=('vuln_sentinel.zip');
-- Or use the stage file uploader / SnowSQL PUT.
CREATE OR REPLACE PROCEDURE VULN_SENTINEL_DB.SERVING.MATCH_CLIENT_ADVISORIES()
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION='3.11'
ARTIFACT_REPOSITORY=snowflake.snowpark.pypi_shared_repository
PACKAGES=('snowflake-snowpark-python','packaging','semantic-version','pydantic')
IMPORTS=('@VULN_SENTINEL_DB.SERVING.APP_CODE/vuln_sentinel.zip')
HANDLER='vuln_sentinel.snowflake_runtime.reconcile'
EXECUTE AS OWNER;

-- Explicitly suspended until warehouse/configuration is verified.
CREATE OR REPLACE TASK VULN_SENTINEL_DB.SERVING.TASK_MATCH_CLIENTS
  WAREHOUSE=DEFAULT_WH
  SCHEDULE='USING CRON 20 * * * * UTC'
  ALLOW_OVERLAPPING_EXECUTION=FALSE
  AS CALL VULN_SENTINEL_DB.SERVING.MATCH_CLIENT_ADVISORIES();
-- CALL VULN_SENTINEL_DB.SERVING.MATCH_CLIENT_ADVISORIES();
-- ALTER TASK VULN_SENTINEL_DB.SERVING.TASK_MATCH_CLIENTS RESUME;
