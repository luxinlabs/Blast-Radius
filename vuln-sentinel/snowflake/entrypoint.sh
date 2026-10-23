#!/bin/sh
# Inside Snowpark Container Services, let the Snowflake connector authenticate with the service's OAuth token.
if [ -n "$SNOWFLAKE_HOST" ]; then
  umask 077
  mkdir -p "$HOME/.snowflake"
  cat > "$HOME/.snowflake/connections.toml" <<TOML
[${SNOWFLAKE_CONNECTION_NAME:-vuln_sentinel}]
account = "$SNOWFLAKE_ACCOUNT"
host = "$SNOWFLAKE_HOST"
authenticator = "oauth"
token_file_path = "/snowflake/session/token"
warehouse = "${SNOWFLAKE_WAREHOUSE:-DEFAULT_WH}"
TOML
fi
exec "$@"
