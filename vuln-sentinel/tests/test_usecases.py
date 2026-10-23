from vuln_sentinel.usecases import heuristic_use_cases, scan_repo

KNOWN = {("npm", "axios"), ("PyPI", "litellm")}


def test_scan_finds_functions_that_call_installed_packages(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules" / "axios").mkdir(parents=True)
    (tmp_path / "node_modules" / "axios" / "index.js").write_text("const axios = require('axios')\n")
    (tmp_path / "src" / "checkout.js").write_text(
        "import axios from 'axios'\nimport fs from 'fs'\n"
        "export async function chargeCard(x) { return axios.post('/charge', x) }\n"
        "const noop = () => 1\n"
    )
    (tmp_path / "gateway.py").write_text(
        "import litellm\nimport os\n\ndef route(msg):\n    return litellm.completion(msg)\n\nlitellm.drop_params = True\n"
    )
    usages = scan_repo(tmp_path, KNOWN)
    assert [(u["package"], u["file"], u["symbol"]) for u in usages] == [
        ("litellm", "gateway.py", "route"),
        ("axios", "src/checkout.js", "chargeCard"),
    ]


def test_heuristic_groups_by_file_and_flags_critical_paths():
    usages = [
        {"ecosystem": "npm", "package": "axios", "file": "src/pay/checkout.js", "symbol": "a"},
        {"ecosystem": "npm", "package": "axios", "file": "src/pay/checkout.js", "symbol": "b"},
        {"ecosystem": "npm", "package": "axios", "file": "src/ui/banner.js", "symbol": "c"},
    ]
    found = {u["name"]: u for u in heuristic_use_cases(usages)}
    assert found["pay checkout"]["criticality"] == "high"
    assert len(found["pay checkout"]["usages"]) == 2
    assert found["ui banner"]["criticality"] == "medium"


def test_usecases_endpoint_stores_inferred_map(stack):
    _, call, service = stack
    body = {
        "usages": [{"ecosystem": "npm", "package": "axios", "file": "src/pay/checkout.js", "symbol": "a"}]
    }
    assert call("POST", "/v1/clients/app/usecases", body, "agent").json() == {
        "client_id": "app",
        "use_cases": 1,
    }
    assert service.store.get_use_cases("app")[0]["name"] == "pay checkout"
    assert call("POST", "/v1/clients/other-app/usecases", body, "agent").status_code == 403
    assert call("POST", "/v1/clients/app/usecases", body, "reader").status_code == 403
