# LiteLLM notification: evidence from the local demo run

This report was read from the running demo's persisted SQLite records. No event or approval was changed to produce it.

## Finding

**Yes: the injected LiteLLM event produced a new THREAT notification at 22:27:55 UTC on October 23, 2026.** The client worker received it at 22:27:56 UTC. The older 22:27:24 log entries belong to Chalk and access anomalies, not this LiteLLM injection.

The source is the operator's synthetic event:

```bash
.venv/bin/sentinel inject pypi litellm 1.106.2 --advisory DEMO-LITELLM-SANDBOX
```

It is not an externally verified claim that LiteLLM 1.106.2 is malicious. The saved response is explicitly marked `synthetic: true`.

## Persisted timeline

All timestamps below are UTC on October 23, 2026.

| Time | Record | Meaning |
|---|---|---|
| 22:27:55.559280 | `threat_events.created_at` | Admin's LiteLLM injection was stored. |
| 22:27:55.570537 | `notifications.created_at` | A new `THREAT` notification was created for `llm-gateway`. |
| 22:27:56.415812 | client job log | Worker recorded that it received the notification. |
| 22:27:56.422807 | `notifications.updated_at` | Worker stored its proposed response; notification status became `RESPONDED`. |
| 22:27:56.425826 | client job log | Worker requested approval to run checks on an isolated copy. |
| 22:30:30.608789 | second `threat_events` entry | The same advisory/version was injected again. The existing incident/notification was reused; no second LiteLLM notification appeared in the inspected records. |

The observed delay from notification creation to worker receipt was approximately **0.85 seconds** in this run. That is a single observed measurement, not a general performance claim.

UTC `22:27:55` is **10:27:55 PM UTC**, or **3:27:55 PM PDT** in America/Los_Angeles on this date.

## IDs linking the records

- First injected threat event: `883e53b4ae6d48e7b78e5171e00d9206`
- Advisory label: `DEMO-LITELLM-SANDBOX`
- Client: `llm-gateway`
- Package: `PyPI/litellm@1.106.2`
- Notification / emergency ID: `1ee8e728632181d42415071f931b807e3c2dfe36a1d729887e78840e6ad87c66`
- Worker job ID: `4cec541154becb75b97f94277df57d7da9a88b17b5db022601e7860e219a657e`
- Worker identity: `client-agent:llm-gateway`
- Inspected notification status: `RESPONDED`
- Inspected sandbox job state: `AWAITING_APPROVAL`

`RESPONDED` means the agent submitted its recommendation. It does not mean code executed, a patch was applied to the client repository, or a deployment was contained.

## Local evidence sources

- `.sentinel/state.sqlite`: `threat_events`, `notifications`, `agent_events`.
- `.sentinel/client-jobs.sqlite`: `jobs`, `logs`.
- [Notification creation and audit code](../src/vuln_sentinel/store.py): `add_threat`, `notify`, `respond_notification`.
- [Worker receipt and approval logging](../src/vuln_sentinel/sandbox.py): `ClientFleet.drain`.
- [Terminal log ordering](../src/vuln_sentinel/client_agent.py): `supervise`.

The watcher prints jobs grouped by client, with newer jobs first inside each group. It does not globally merge every log line chronologically. That is why a 22:27:56 LiteLLM block can be followed by 22:27:24 access-anomaly blocks.

## Recheck notification timestamps yourself

From `vuln-sentinel`:

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path
import sqlite3

path = Path('.sentinel/state.sqlite').resolve()
with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as conn:
    for identity, status, created, updated, raw in conn.execute(
        "SELECT notification_id,status,created_at,updated_at,payload "
        "FROM notifications WHERE client_id='llm-gateway' AND kind='THREAT' "
        "ORDER BY created_at"
    ):
        payload = json.loads(raw)
        if payload.get('package', {}).get('name') == 'litellm':
            print(json.dumps({
                'notification_id': identity,
                'status': status,
                'created_at_utc': created,
                'updated_at_utc': updated,
                'package': payload['package'],
                'synthetic': payload.get('synthetic'),
                'advisories': [a['advisory_id'] for a in payload.get('advisories', [])],
            }, indent=2))
PY
```

Use the SQLite path configured for the running API if it differs from the default. These metadata queries do not print tokens or secret values.
