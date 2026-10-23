"""Run numbered SQL files against Snowflake: python scripts/deploy_snowflake.py 02 03 ... (or 10 11 13 14 15).

Uses the named connection from connections.toml. File 01 replaces the database, so it needs --fresh.
"""

import argparse
import os
from pathlib import Path

import snowflake.connector

parser = argparse.ArgumentParser()
parser.add_argument("steps", nargs="+", help="Two-digit prefixes of files in sql/, run in numeric order")
parser.add_argument(
    "--fresh", action="store_true", help="Allow step 01 (drops and recreates VULN_SENTINEL_DB)"
)
args = parser.parse_args()
if "01" in args.steps and not args.fresh:
    parser.error("Step 01 replaces the populated database; pass --fresh if that is intended")
sql_dir = Path(__file__).resolve().parents[1] / "sql"
with snowflake.connector.connect(
    connection_name=os.getenv("SNOWFLAKE_CONNECTION_NAME", "vuln_sentinel")
) as conn:
    for step in sorted(args.steps):
        (path,) = sql_dir.glob(f"{step}_*.sql")
        print(f"Running {path.name}", flush=True)
        # Trailing comment-only text would otherwise be sent as an empty statement.
        conn.execute_string(path.read_text(), remove_comments=True)
