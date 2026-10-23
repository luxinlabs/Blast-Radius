# Snowflake deployment

Not run against a live account yet; every step below is unverified until someone does it.

| Piece | File | Notes |
|---|---|---|
| Base schema, advisories, packages | `sql/01`–`09` | `01` drops and recreates `VULN_SENTINEL_DB`. `07` loads OSV and registry data (slow). |
| Tracking tables, intel feed | `sql/10`, `11` | Additive. `11` replaces `IS_AFFECTED` and `RESPOND`. |
| Native matching task | `sql/12` + `dist/vuln_sentinel.zip` | Rebuild the zip with `python scripts/package_snowflake.py` after editing packaged modules, and commit it (CI checks). |
| Roles | `sql/13` | Assign `VULN_SENTINEL_APP` to the service user. |
| Notifications, use cases, threats | `sql/15` | Also grants `SNOWFLAKE.CORTEX_USER` (use-case naming). |
| App hosting | `snowflake/spcs.sql`, `snowflake/service.yaml`, `snowflake/entrypoint.sh` | Container service for API + dashboard. Needs compute-pool privileges; the public endpoint requires a Snowflake login. |

Run SQL: add a `vuln_sentinel` connection to `~/.snowflake/connections.toml`, then `python scripts/deploy_snowflake.py 10 11 13 14 15` (add `--fresh` only to allow step `01`).

Switch the app: `SENTINEL_BACKEND=snowflake`, `SNOWFLAKE_CONNECTION_NAME=vuln_sentinel`, then `sentinel serve`. Check: `POST /v1/respond` for a known package returns advisories from Snowflake instead of `demo: true`.

Container image: `docker build -t vuln-sentinel .` works locally; push it to the repository that `SHOW IMAGE REPOSITORIES` prints. Never reuse the local demo tokens in the Snowflake secret.
