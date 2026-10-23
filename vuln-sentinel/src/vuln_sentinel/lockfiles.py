"""Parse exact versions without executing a package manager or resolving latest tags."""

import json
import re
import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from .models import SBOM, Package, normalize


def parse_lockfile(path: str | Path) -> SBOM:
    path = Path(path)
    if path.name == "package-lock.json":
        return npm_lock(path)
    if path.name == "poetry.lock":
        return poetry_lock(path)
    if path.suffix == ".txt":
        return requirements(path)
    raise ValueError("Use package-lock.json, poetry.lock, or exact-pinned requirements.txt")


def npm_lock(path):
    data = json.loads(path.read_text())
    warnings = []
    entries = data.get("packages")
    if entries is None:
        # v1 locks encode the installed tree recursively.
        entries = {"": {"dependencies": {}}}

        def flatten(tree, parent=""):
            for name, item in tree.items():
                location = f"{parent + '/' if parent else ''}node_modules/{name}"
                entries[location] = {**item, "dependencies": item.get("requires", {})}
                if not parent:
                    entries[""]["dependencies"][name] = item.get("version")
                flatten(item.get("dependencies", {}), location)

        flatten(data.get("dependencies", {}))
        warnings.append("npm v1 root directness is inferred; use npm v2/v3 locks for precise root metadata")
    root = entries.get("", {})
    direct = set().union(
        *(set(root.get(k, {})) for k in ("dependencies", "devDependencies", "optionalDependencies"))
    )
    packages = {}
    for location, item in entries.items():
        if not location:
            continue
        if item.get("link") or "node_modules/" not in location or not item.get("version"):
            warnings.append(f"Unresolved workspace/local entry: {location}")
            continue
        name = item.get("name") or location.rsplit("node_modules/", 1)[1]
        # Alias version entries with actual package name absent cannot be reliably attributed.
        p = Package(
            ecosystem="npm",
            name=name,
            version=item["version"],
            locator=location,
            direct=location == f"node_modules/{name}" and name in direct,
        )
        packages[location] = p

    def resolve(location, name):
        candidate = f"{location}/node_modules/{name}"
        if candidate in packages:
            return candidate
        current = location
        while "/node_modules/" in current:
            current = current.rsplit("/node_modules/", 1)[0]
            candidate = f"{current}/node_modules/{name}"
            if candidate in packages:
                return candidate
        candidate = f"node_modules/{name}"
        return candidate if candidate in packages else None

    for location, p in packages.items():
        item = entries[location]
        names = set().union(
            *(set(item.get(k, {})) for k in ("dependencies", "peerDependencies", "optionalDependencies"))
        )
        optional = set(item.get("optionalDependencies", {})) | {
            n for n, meta in item.get("peerDependenciesMeta", {}).items() if meta.get("optional")
        }
        for name in sorted(names):
            child = resolve(location, name)
            if child:
                p.dependencies.append(child)
            elif name not in optional:
                warnings.append(f"Unresolved dependency: {location} -> {name}")
    if not packages:
        raise ValueError("No exact registry versions found in lockfile")
    return SBOM(
        source=path.name,
        packages=sorted(packages.values(), key=lambda p: p.locator),
        graph_complete=not warnings,
        warnings=warnings,
    )


def poetry_lock(path):
    data = tomllib.loads(path.read_text())
    packages, index = [], {}
    for i, item in enumerate(data.get("package", [])):
        name = normalize("pypi", item["name"])[1]
        p = Package(
            ecosystem="pypi",
            name=name,
            version=item["version"],
            locator=f"poetry:{name}@{item['version']}:{i}",
        )
        packages.append(p)
        index.setdefault(name, []).append(p.locator)
    warnings = [
        "Poetry lock includes conditional/optional packages; edges are conservative across environments"
    ]
    for p, item in zip(packages, data.get("package", [])):
        for name in item.get("dependencies", {}):
            normalized = normalize("pypi", name)[1]
            if normalized == "python":
                continue
            if normalized not in index:
                warnings.append(f"Unresolved dependency: {p.name} -> {normalized}")
            p.dependencies.extend(index.get(normalized, []))
    return SBOM(source=path.name, packages=packages, graph_complete=False, warnings=warnings)


def requirements(path):
    packages, warnings = (
        {},
        ["requirements.txt has no resolved dependency graph; upload a lockfile for blast radius"],
    )
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        # Do not pretend constraints, editable URLs, includes or hashes are exact resolved inventories.
        if line.startswith("-") or " --hash" in line or line.endswith("\\"):
            raise ValueError(
                f"Line {line_no}: use a flattened, exact-pinned requirements file without directives/hashes"
            )
        try:
            req = Requirement(line)
        except InvalidRequirement as exc:
            raise ValueError(f"Line {line_no}: invalid requirement") from exc
        specs = list(req.specifier)
        if req.url or len(specs) != 1 or specs[0].operator != "==" or "*" in specs[0].version:
            raise ValueError(f"Line {line_no}: {req.name} must use one exact == pin")
        p = Package(ecosystem="pypi", name=req.name, version=specs[0].version, direct=True)
        p.locator = f"requirements:{p.name}@{p.version}"
        packages[p.locator] = p
        if req.marker:
            warnings.append(f"{p.name}: conditional pin included conservatively ({req.marker})")
    return SBOM(
        source=path.name,
        packages=sorted(packages.values(), key=lambda p: p.locator),
        graph_complete=False,
        warnings=warnings,
    )
