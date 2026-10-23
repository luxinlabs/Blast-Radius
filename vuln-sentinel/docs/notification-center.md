# Notification center

One feed for every detector. Table `notifications`; the autonomous code agent reads it ([AUTONOMOUS_CODE.md](AUTONOMOUS_CODE.md) has full payloads).

| Call | Role | Result |
|---|---|---|
| `GET /v1/notifications?client_id=&status=` | Any role for its client; no `client_id` = admin | List, newest first: `{notification_id, client_id, kind, priority, status, payload, response, created_at, updated_at}` |
| `POST /v1/notifications/{id}/response` | `agent` for the client, or admin | `{"status": "RESPONDED", "requires_human_approval": true}` |

- `kind`: `THREAT` (id = the incident's `emergency_id`), `IOC_MATCH`, `ACCESS_ANOMALY`.
- `status`: `NEW` → `RESPONDED`, once. `409` if already answered, unknown, or the threat's incident was superseded.
- Response body: `{summary, actions: [{type, target, rationale, artifacts: [{kind, ref, content}]}]}`. Unknown fields or action types are `422`. Nothing the agent returns is executed by the server.
- Notifications are created in the same transaction as the incident or report, and are idempotent. A reopened incident returns to `NEW`.

Try: `curl -H "Authorization: Bearer $SENTINEL_ADMIN_TOKEN" "$SENTINEL_URL/v1/notifications?status=NEW"`.
