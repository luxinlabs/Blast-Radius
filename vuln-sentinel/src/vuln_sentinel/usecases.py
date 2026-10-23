"""Code-usage scanning and use-case labelling. Only file paths and symbol names leave the client."""

import ast
import re
from pathlib import Path

from .models import normalize

SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
CRITICAL = ("pay", "checkout", "billing", "auth", "login", "secret", "key", "token", "crypto")
JS_IMPORT = re.compile(
    r"""(?:import\s+(?P<a>[^'"\n]*?)\s+from\s+|(?:const|let|var)\s+(?P<b>[^=\n]+?)\s*=\s*require\()\s*['"](?P<pkg>[^'"]+)['"]"""
)
JS_FUNC = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>)",
    re.M,
)


def python_usages(text, known):
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[(a.asname or a.name).split(".")[0]] = a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                aliases[a.asname or a.name] = node.module.split(".")[0]
    packages = {local: normalize("pypi", module)[1] for local, module in aliases.items()}
    packages = {local: p for local, p in packages.items() if ("PyPI", p) in known}
    found = set()
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            found |= {
                ("PyPI", packages[n.id], fn.name)
                for n in ast.walk(fn)
                if isinstance(n, ast.Name) and n.id in packages
            }
    used = {p for _, p, _ in found}
    return found | {("PyPI", p, "<module>") for p in set(packages.values()) - used}


def js_usages(text, known):
    aliases = {}
    for m in JS_IMPORT.finditer(text):
        spec = m["pkg"]
        if spec.startswith("."):
            continue
        name = "/".join(spec.split("/")[: 2 if spec.startswith("@") else 1])
        if ("npm", name) in known:
            aliases.update({w: name for w in re.findall(r"\w+", m["a"] or m["b"]) if w != "as"})
    starts = [(m.start(), m[1] or m[2]) for m in JS_FUNC.finditer(text)]
    bounds = [*starts, (len(text), None)]
    found = set()
    for (start, symbol), (end, _) in zip(bounds, bounds[1:]):
        body = text[start:end]
        found |= {("npm", pkg, symbol) for alias, pkg in aliases.items() if re.search(rf"\b{alias}\b", body)}
    used = {p for _, p, _ in found}
    return found | {("npm", p, "<module>") for p in set(aliases.values()) - used}


def scan_repo(root, known):
    """Usages of installed packages (`known` is a set of (ecosystem, name)) in the repo's source."""
    root, usages = Path(root), set()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if SKIP & set(rel.parts) or path.suffix not in {".py", ".js", ".mjs", ".jsx", ".ts", ".tsx"}:
            continue
        scan = python_usages if path.suffix == ".py" else js_usages
        usages |= {
            (eco, pkg, rel.as_posix(), sym) for eco, pkg, sym in scan(path.read_text(errors="replace"), known)
        }
    return [dict(zip(("ecosystem", "package", "file", "symbol"), u)) for u in sorted(usages)]


def group(usages, labels):
    """Cluster usages by the (name, criticality) label of their file."""
    groups = {}
    for u in usages:
        name, criticality = labels[u["file"]]
        groups.setdefault(name, {"name": name, "criticality": criticality, "usages": []})["usages"].append(u)
    return list(groups.values())


def heuristic_use_cases(usages):
    labels = {}
    for f in {u["file"] for u in usages}:
        name = re.sub(r"[-_]+", " ", " ".join(Path(f).with_suffix("").parts[-2:]))
        labels[f] = (name, "high" if any(k in name for k in CRITICAL) else "medium")
    return group(usages, labels)
