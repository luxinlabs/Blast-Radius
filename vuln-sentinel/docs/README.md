# Component guide

Each file below states one component's input, output and a command to try it. Run everything from `vuln-sentinel/`.

| Component | Who runs it | Doc |
|---|---|---|
| Client agent (`sentinel` CLI) | Client device | [client-agent.md](client-agent.md) |
| Use-case mapping | Client device → server | [usecase-mapping.md](usecase-mapping.md) |
| Response engine (scan, reconcile, respond) | Server | [response-engine.md](response-engine.md) |
| Threats and impact | Server (demo injection is admin-only) | [threats-and-impact.md](threats-and-impact.md) |
| Access monitor | Client device → server | [access-monitor.md](access-monitor.md) |
| Notification center | Server | [notification-center.md](notification-center.md) |
| Autonomous code agent | Teammate | [AUTONOMOUS_CODE.md](AUTONOMOUS_CODE.md) |
| Fix and human review | Client device + reviewer | [fix-and-review.md](fix-and-review.md) |
| Snowflake deployment | Whoever has the account | [snowflake.md](snowflake.md) |

## Test run everything (local, no Snowflake)

```bash
cd vuln-sentinel
python3.12 -m venv .venv && . .venv/bin/activate
pip install -c constraints.txt -e '.[dev,snowflake]'
sentinel init-demo                  # skip if .env already exists
python scripts/test.py -q           # expect all tests to pass
ruff check src tests scripts && ruff format --check src tests scripts

rm -rf .sentinel                    # reset demo state
sentinel demo-orgs                  # three fake client orgs
sentinel serve --port 8010 &        # 8000 may be taken
export SENTINEL_URL=http://127.0.0.1:8010
sentinel inject npm chalk 5.6.2 --advisory DEMO-CHALK
sentinel dashboard                  # http://127.0.0.1:8501, paste SENTINEL_ADMIN_TOKEN from .env
```

Export `SENTINEL_URL` after sourcing `.env` if you use `curl` with its tokens (`. ./.env`), because `.env` sets it to port 8000. The `sentinel` CLI itself keeps an already-exported `SENTINEL_URL`. On first launch Streamlit may ask for an email in the terminal; press Enter to skip.

In the dashboard, leave Client ID blank for the fleet view or enter `acme-pay`, `buildkit` or `llm-gateway` for that org's use-case impact. Expected after the inject above: `acme-pay` and `buildkit` each have a `THREAT`, `llm-gateway` has three `ACCESS_ANOMALY` notifications.

Other injections: `sentinel inject npm axios 1.20.0` (acme-pay checkout and login), `sentinel inject pypi litellm 1.106.2` (llm-gateway router).

Stop the server with `kill %1`. Tokens live in `.env` (gitignored); never paste them into docs or commits.
