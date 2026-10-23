"""Test launcher; avoids a crashing optional libreadline in some macOS Conda distributions."""

import sys

sys.modules["readline"] = None
import pytest  # noqa: E402

raise SystemExit(pytest.main(sys.argv[1:] or ["-q"]))
