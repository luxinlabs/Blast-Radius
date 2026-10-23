CREATE OR REPLACE FUNCTION VULN_SENTINEL_DB.CORE.IS_AFFECTED("ECOSYSTEM" VARCHAR, "VER" VARCHAR, "INTRODUCED" VARCHAR, "FIXED" VARCHAR, "LAST_AFFECTED" VARCHAR, "AFFECTED_VERSIONS" ARRAY)
RETURNS BOOLEAN
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
ARTIFACT_REPOSITORY = snowflake.snowpark.pypi_shared_repository
PACKAGES = ('packaging')
HANDLER = 'f'
AS '
import re
from packaging.version import Version, InvalidVersion

def _semver(v):
    v = v.strip().lstrip(''v'').split(''+'')[0]
    core, _, pre = v.partition(''-'')
    nums = [int(x) if x.isdigit() else 0 for x in (core.split(''.'') + [''0'',''0''])[:3]]
    # a release sorts after any of its prereleases
    pre_key = (1,) if not pre else (0,) + tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split(''.''))
    return (tuple(nums), pre_key)

def _key(eco, v):
    if eco == ''PyPI'':
        try:
            return (0, Version(v))
        except InvalidVersion:
            return None
    try:
        return (0, _semver(v))
    except Exception:
        return None

def f(eco, ver, intro, fixed, last, versions):
    if ver is None:
        return None
    if versions and ver in versions:
        return True
    if not intro and not fixed and not last:
        return False
    k = _key(eco, ver)
    if k is None:
        return None
    if intro and intro != ''0'':
        ki = _key(eco, intro)
        if ki is not None and k < ki:
            return False
    if fixed:
        kf = _key(eco, fixed)
        return kf is not None and k < kf
    if last:
        kl = _key(eco, last)
        return kl is not None and k <= kl
    return True
';

CREATE OR REPLACE PROCEDURE VULN_SENTINEL_DB.CORE.MERGE_OSV("ECOSYSTEM" VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS '
BEGIN
  MERGE INTO VULN_SENTINEL_DB.CORE.ADVISORIES t
  USING (
    SELECT r.ID AS ADVISORY_ID, r.ECOSYSTEM,
           COALESCE(r.RECORD:aliases, ARRAY_CONSTRUCT())::ARRAY AS ALIASES,
           ARRAY_CAT(
             IFF(STARTSWITH(r.ID, ''CVE-''), ARRAY_CONSTRUCT(r.ID), ARRAY_CONSTRUCT()),
             FILTER(COALESCE(r.RECORD:aliases, ARRAY_CONSTRUCT())::ARRAY, a -> STARTSWITH(a::STRING, ''CVE-''))) AS CVE_IDS,
           r.RECORD:summary::STRING AS SUMMARY,
           LEFT(r.RECORD:details::STRING, 8000) AS DETAILS,
           UPPER(COALESCE(r.RECORD:database_specific:severity::STRING,
                 IFF(STARTSWITH(r.ID, ''MAL-''), ''CRITICAL'', NULL))) AS SEVERITY,
           r.RECORD:severity[0]:score::STRING AS CVSS_VECTOR,
           r.RECORD:published::TIMESTAMP_TZ AS PUBLISHED,
           r.MODIFIED,
           r.RECORD:withdrawn::TIMESTAMP_TZ AS WITHDRAWN,
           r.RECORD:references::ARRAY AS REFERENCES
    FROM VULN_SENTINEL_DB.RAW.OSV_RECORDS r
    WHERE r.ECOSYSTEM = :ECOSYSTEM
  ) s ON t.ADVISORY_ID = s.ADVISORY_ID
  WHEN MATCHED AND s.MODIFIED > t.MODIFIED THEN UPDATE SET
    ALIASES = s.ALIASES, CVE_IDS = s.CVE_IDS, SUMMARY = s.SUMMARY, DETAILS = s.DETAILS,
    SEVERITY = s.SEVERITY, CVSS_VECTOR = s.CVSS_VECTOR, MODIFIED = s.MODIFIED,
    WITHDRAWN = s.WITHDRAWN, REFERENCES = s.REFERENCES
  WHEN NOT MATCHED THEN INSERT VALUES (s.ADVISORY_ID, s.ECOSYSTEM, s.ALIASES, s.CVE_IDS, s.SUMMARY,
    s.DETAILS, s.SEVERITY, s.CVSS_VECTOR, s.PUBLISHED, s.MODIFIED, s.WITHDRAWN, s.REFERENCES);

  DELETE FROM VULN_SENTINEL_DB.CORE.AFFECTED_RANGES WHERE ECOSYSTEM = :ECOSYSTEM;
  INSERT INTO VULN_SENTINEL_DB.CORE.AFFECTED_RANGES
  SELECT r.ID, r.ECOSYSTEM,
         af.value:package:name::STRING,
         rg.value:type::STRING,
         MAX(ev.value:introduced::STRING),
         MAX(ev.value:fixed::STRING),
         MAX(ev.value:last_affected::STRING),
         ANY_VALUE(af.value:versions::ARRAY)
  FROM VULN_SENTINEL_DB.RAW.OSV_RECORDS r,
       LATERAL FLATTEN(INPUT => r.RECORD:affected) af,
       LATERAL FLATTEN(INPUT => af.value:ranges, OUTER => TRUE) rg,
       LATERAL FLATTEN(INPUT => rg.value:events, OUTER => TRUE) ev
  WHERE r.ECOSYSTEM = :ECOSYSTEM
  GROUP BY r.ID, r.ECOSYSTEM, af.value:package:name::STRING, rg.value:type::STRING, af.index, rg.index;

  RETURN ''merged '' || :ECOSYSTEM;
END;
';

CREATE OR REPLACE PROCEDURE VULN_SENTINEL_DB.CORE.MERGE_REGISTRY("ECOSYSTEM" VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS '
BEGIN
  MERGE INTO VULN_SENTINEL_DB.CORE.PACKAGES t
  USING (
    SELECT r.ECOSYSTEM, r.NAME,
           r.RECORD:latest::STRING LATEST_VERSION, r.RECORD:description::STRING DESCRIPTION,
           r.RECORD:license::STRING LICENSE, r.RECORD:repository::STRING REPOSITORY,
           r.RECORD:homepage::STRING HOMEPAGE, r.RECORD:maintainers::ARRAY MAINTAINERS,
           r.DOWNLOADS MONTHLY_DOWNLOADS,
           ARRAY_SIZE(OBJECT_KEYS(r.RECORD:versions)) VERSION_COUNT,
           r.RECORD:last_published::TIMESTAMP_TZ LAST_PUBLISHED
    FROM VULN_SENTINEL_DB.RAW.REGISTRY_RECORDS r WHERE r.ECOSYSTEM = :ECOSYSTEM
    QUALIFY ROW_NUMBER() OVER (PARTITION BY r.ECOSYSTEM, r.NAME ORDER BY r.LOADED_AT DESC) = 1
  ) s ON t.ECOSYSTEM = s.ECOSYSTEM AND t.NAME = s.NAME
  WHEN MATCHED THEN UPDATE SET LATEST_VERSION = s.LATEST_VERSION, DESCRIPTION = s.DESCRIPTION, LICENSE = s.LICENSE,
    REPOSITORY = s.REPOSITORY, HOMEPAGE = s.HOMEPAGE, MAINTAINERS = s.MAINTAINERS,
    MONTHLY_DOWNLOADS = s.MONTHLY_DOWNLOADS, VERSION_COUNT = s.VERSION_COUNT,
    LAST_PUBLISHED = s.LAST_PUBLISHED, UPDATED_AT = CURRENT_TIMESTAMP()
  WHEN NOT MATCHED THEN INSERT VALUES (s.ECOSYSTEM, s.NAME, s.LATEST_VERSION, s.DESCRIPTION, s.LICENSE, s.REPOSITORY,
    s.HOMEPAGE, s.MAINTAINERS, s.MONTHLY_DOWNLOADS, s.VERSION_COUNT, s.LAST_PUBLISHED, CURRENT_TIMESTAMP());

  DELETE FROM VULN_SENTINEL_DB.CORE.PACKAGE_VERSIONS WHERE ECOSYSTEM = :ECOSYSTEM;
  INSERT INTO VULN_SENTINEL_DB.CORE.PACKAGE_VERSIONS
  SELECT r.ECOSYSTEM, r.NAME, v.key, TRY_TO_TIMESTAMP_TZ(v.value:time::STRING),
         COALESCE(v.value:yanked::BOOLEAN, FALSE), v.value:deprecated::STRING
  FROM VULN_SENTINEL_DB.RAW.REGISTRY_RECORDS r, LATERAL FLATTEN(r.RECORD:versions) v
  WHERE r.ECOSYSTEM = :ECOSYSTEM
  QUALIFY ROW_NUMBER() OVER (PARTITION BY r.ECOSYSTEM, r.NAME, v.key ORDER BY r.LOADED_AT DESC) = 1;
  RETURN ''merged registry '' || :ECOSYSTEM;
END;
';

CREATE OR REPLACE PROCEDURE VULN_SENTINEL_DB.RAW.INGEST_DEPENDENCIES("MAX_DEPTH" NUMBER(38,0) DEFAULT 3, "MAX_PACKAGES" NUMBER(38,0) DEFAULT 600)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
ARTIFACT_REPOSITORY = snowflake.snowpark.pypi_shared_repository
PACKAGES = ('snowflake-snowpark-python','requests','packaging')
HANDLER = 'run'
EXTERNAL_ACCESS_INTEGRATIONS = (BLAST_RADIUS_PUBLIC_EAI)
COMMENT='Fetch declared runtime dependencies of the latest version for watchlist packages, expanded breadth-first'
EXECUTE AS OWNER
AS '
import requests, re, datetime
from concurrent.futures import ThreadPoolExecutor
from packaging.requirements import Requirement

S = requests.Session()
S.headers[''User-Agent''] = ''vuln-sentinel/0.1 (open-source dependency response)''

def norm_py(n):
    return re.sub(r''[-_.]+'', ''-'', n).lower()

def fetch(key):
    eco, name = key
    try:
        if eco == ''npm'':
            r = S.get(f''https://registry.npmjs.org/{name.replace("/", "%2F")}/latest'', timeout=20)
            if r.status_code != 200:
                return key, None, [], str(r.status_code)
            j = r.json()
            out = [(d, spec, ''runtime'') for d, spec in (j.get(''dependencies'') or {}).items()]
            out += [(d, spec, ''peer'') for d, spec in (j.get(''peerDependencies'') or {}).items()]
            return key, j.get(''version''), out, None
        r = S.get(f''https://pypi.org/pypi/{name}/json'', timeout=20)
        if r.status_code != 200:
            return key, None, [], str(r.status_code)
        info = r.json()[''info'']
        out = []
        for line in info.get(''requires_dist'') or []:
            try:
                req = Requirement(line)
            except Exception:
                continue
            m = str(req.marker or '''')
            kind = ''optional'' if ''extra'' in m else ''runtime''
            out.append((norm_py(req.name), str(req.specifier), kind))
        return key, info.get(''version''), out, None
    except Exception as e:
        return key, None, [], str(e)[:200]

def run(session, max_depth, max_packages):
    seeds = [(r[''ECOSYSTEM''], r[''NAME'']) for r in session.sql(
        ''SELECT ecosystem, name FROM VULN_SENTINEL_DB.CORE.WATCHLIST'').collect()]
    seen, frontier, rows, errors = set(seeds), list(seeds), [], []
    now = datetime.datetime.utcnow()
    for depth in range(int(max_depth)):
        if not frontier:
            break
        with ThreadPoolExecutor(16) as ex:
            results = list(ex.map(fetch, frontier))
        nxt = []
        for (eco, name), ver, deps, err in results:
            if err:
                errors.append(f''{eco}:{name}:{err}'')
            for d, spec, kind in deps:
                rows.append((eco, name, ver, d, spec, kind, depth, now))
                k = (eco, d)
                # only follow required runtime edges to keep the graph honest and small
                if kind == ''runtime'' and k not in seen and len(seen) < max_packages:
                    seen.add(k); nxt.append(k)
        frontier = nxt
    cols = [''ECOSYSTEM'',''PARENT'',''PARENT_VERSION'',''CHILD'',''VERSION_SPEC'',''DEP_KIND'',''DEPTH'',''LOADED_AT'']
    session.sql(''''''CREATE TABLE IF NOT EXISTS VULN_SENTINEL_DB.CORE.DEPENDENCIES (
        ECOSYSTEM STRING, PARENT STRING, PARENT_VERSION STRING, CHILD STRING, VERSION_SPEC STRING,
        DEP_KIND STRING, DEPTH NUMBER, LOADED_AT TIMESTAMP_NTZ)'''''').collect()
    if rows:
        df = session.create_dataframe(rows, schema=cols)
        df.write.save_as_table(''VULN_SENTINEL_DB.CORE.DEPENDENCIES_STAGE'', mode=''overwrite'')
        session.sql(''''''CREATE OR REPLACE TABLE VULN_SENTINEL_DB.CORE.DEPENDENCIES AS
            SELECT DISTINCT * FROM VULN_SENTINEL_DB.CORE.DEPENDENCIES_STAGE'''''').collect()
        session.sql(''DROP TABLE VULN_SENTINEL_DB.CORE.DEPENDENCIES_STAGE'').collect()
    return {''packages_visited'': len(seen), ''edges'': len(rows), ''errors'': errors[:20], ''error_count'': len(errors)}
';

CREATE OR REPLACE PROCEDURE VULN_SENTINEL_DB.RAW.INGEST_OSV("ECOSYSTEM" VARCHAR)
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
ARTIFACT_REPOSITORY = snowflake.snowpark.pypi_shared_repository
PACKAGES = ('snowflake-snowpark-python','requests')
HANDLER = 'run'
EXTERNAL_ACCESS_INTEGRATIONS = (BLAST_RADIUS_PUBLIC_EAI)
EXECUTE AS OWNER
AS '
import gzip, io, json, os, tempfile, zipfile
import requests

def run(session, ecosystem):
    url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
    resp = requests.get(url, timeout=600)
    resp.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(resp.content))

    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, f"osv_{ecosystem.lower()}.json.gz")
    n = 0
    with gzip.open(path, "wt", encoding="utf-8") as out:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            rec = json.loads(zf.read(name))
            out.write(json.dumps({"id": rec.get("id"), "ecosystem": ecosystem,
                                  "modified": rec.get("modified"), "record": rec}) + "\\n")
            n += 1

    stage_path = f"@VULN_SENTINEL_DB.RAW.LANDING/osv/{ecosystem}"
    session.file.put(path, stage_path, auto_compress=False, overwrite=True)

    session.sql("DELETE FROM VULN_SENTINEL_DB.RAW.OSV_RECORDS WHERE ECOSYSTEM = ?", params=[ecosystem]).collect()
    session.sql(f"""
        COPY INTO VULN_SENTINEL_DB.RAW.OSV_RECORDS (ID, ECOSYSTEM, MODIFIED, RECORD)
        FROM (SELECT $1:id::STRING, $1:ecosystem::STRING, $1:modified::TIMESTAMP_TZ, $1:record FROM {stage_path})
        FILE_FORMAT = (TYPE = JSON COMPRESSION = GZIP) FORCE = TRUE
    """).collect()

    session.call("VULN_SENTINEL_DB.CORE.MERGE_OSV", ecosystem)
    return f"{ecosystem}: loaded {n} OSV records"
';

CREATE OR REPLACE PROCEDURE VULN_SENTINEL_DB.RAW.INGEST_REGISTRY("ECOSYSTEM" VARCHAR, "TOP_N" NUMBER(38,0))
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
ARTIFACT_REPOSITORY = snowflake.snowpark.pypi_shared_repository
PACKAGES = ('snowflake-snowpark-python','requests')
HANDLER = 'run'
EXTERNAL_ACCESS_INTEGRATIONS = (BLAST_RADIUS_PUBLIC_EAI)
EXECUTE AS OWNER
AS '
import gzip, io, json, os, re, tarfile, tempfile, urllib.parse
from concurrent.futures import ThreadPoolExecutor
import requests

http = requests.Session()
http.mount("https://", requests.adapters.HTTPAdapter(pool_maxsize=64, max_retries=3))

def top_pypi(n):
    data = http.get("https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json", timeout=60).json()
    return {r["project"]: r["download_count"] for r in data["rows"][:n]}

def top_npm(n):
    meta = http.get("https://registry.npmjs.org/npm-high-impact/latest", timeout=60).json()
    tgz = http.get(meta["dist"]["tarball"], timeout=120).content
    names = []
    with tarfile.open(fileobj=io.BytesIO(tgz)) as tf:
        for m in tf.getmembers():
            if m.name.endswith(("lib/top.js", "lib/top-download.js")):
                names += re.findall(r"''([^'']+)''", tf.extractfile(m).read().decode())
    seen, out = set(), []
    for x in names:
        if x not in seen:
            seen.add(x); out.append(x)
    return {x: None for x in out[:n]}

def fetch_pypi(name):
    r = http.get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json", timeout=30)
    if r.status_code != 200:
        return None
    d = r.json(); info = d.get("info", {})
    versions = {}
    for v, files in (d.get("releases") or {}).items():
        if files:
            versions[v] = {"time": min(f["upload_time_iso_8601"] for f in files),
                           "yanked": all(f.get("yanked") for f in files)}
    return {"name": info.get("name") or name, "latest": info.get("version"),
            "description": info.get("summary"), "license": (info.get("license") or "")[:500] or info.get("license_expression"),
            "repository": (info.get("project_urls") or {}).get("Source") or (info.get("project_urls") or {}).get("Repository"),
            "homepage": info.get("home_page") or (info.get("project_urls") or {}).get("Homepage"),
            "maintainers": [m for m in [info.get("author"), info.get("maintainer")] if m],
            "versions": versions}

def fetch_npm(name):
    r = http.get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe=''@'')}", timeout=60)
    if r.status_code != 200:
        return None
    d = r.json(); times = d.get("time", {})
    vers = d.get("versions", {})
    repo = d.get("repository")
    return {"name": d.get("name") or name, "latest": (d.get("dist-tags") or {}).get("latest"),
            "description": d.get("description"),
            "license": d.get("license") if isinstance(d.get("license"), str) else None,
            "repository": repo.get("url") if isinstance(repo, dict) else repo,
            "homepage": d.get("homepage"),
            "maintainers": [m.get("name") for m in d.get("maintainers", []) if isinstance(m, dict)],
            "versions": {v: {"time": times.get(v), "deprecated": (vers[v] or {}).get("deprecated")} for v in vers}}

def npm_downloads(names):
    out = {}
    unscoped = [n for n in names if not n.startswith("@")]
    for i in range(0, len(unscoped), 128):
        chunk = unscoped[i:i + 128]
        r = http.get("https://api.npmjs.org/downloads/point/last-month/" + ",".join(chunk), timeout=60)
        if r.status_code == 200:
            for k, v in r.json().items():
                if v:
                    out[k] = v.get("downloads")
    return out

def run(session, ecosystem, top_n):
    top_n = int(top_n)
    advisory_pkgs = [r[0] for r in session.sql("""
        SELECT DISTINCT PACKAGE_NAME FROM VULN_SENTINEL_DB.CORE.AFFECTED_RANGES
        WHERE ECOSYSTEM = ? AND NOT STARTSWITH(ADVISORY_ID, ''MAL-'') AND PACKAGE_NAME IS NOT NULL""",
        params=[ecosystem]).collect()]
    if ecosystem == "PyPI":
        top, fetch = top_pypi(top_n), fetch_pypi
    else:
        top, fetch = top_npm(top_n), fetch_npm
    names = list(dict.fromkeys(list(top) + advisory_pkgs))

    with ThreadPoolExecutor(max_workers=48) as ex:
        results = list(ex.map(lambda n: (n, fetch(n)), names))
    dl = npm_downloads([n for n, r in results if r]) if ecosystem == "npm" else top

    path = os.path.join(tempfile.mkdtemp(), f"reg_{ecosystem.lower()}.json.gz")
    ok = 0
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for n, rec in results:
            if rec:
                times = [v.get("time") for v in rec["versions"].values() if v.get("time")]
                rec["last_published"] = max(times) if times else None
                f.write(json.dumps({"ecosystem": ecosystem, "name": rec["name"], "downloads": dl.get(n), "record": rec}) + "\\n")
                ok += 1

    stage_path = f"@VULN_SENTINEL_DB.RAW.LANDING/registry/{ecosystem}"
    session.file.put(path, stage_path, auto_compress=False, overwrite=True)
    session.sql("DELETE FROM VULN_SENTINEL_DB.RAW.REGISTRY_RECORDS WHERE ECOSYSTEM = ?", params=[ecosystem]).collect()
    session.sql(f"""
        COPY INTO VULN_SENTINEL_DB.RAW.REGISTRY_RECORDS (ECOSYSTEM, NAME, RECORD, DOWNLOADS)
        FROM (SELECT $1:ecosystem::STRING, $1:name::STRING, $1:record, $1:downloads::NUMBER FROM {stage_path})
        FILE_FORMAT = (TYPE = JSON COMPRESSION = GZIP) FORCE = TRUE""").collect()
    session.call("VULN_SENTINEL_DB.CORE.MERGE_REGISTRY", ecosystem)
    return f"{ecosystem}: requested {len(names)}, loaded {ok} packages"
';

CREATE OR REPLACE PROCEDURE VULN_SENTINEL_DB.SERVING.REFRESH("MODE" VARCHAR DEFAULT 'ADVISORIES')
RETURNS VARCHAR
LANGUAGE SQL
COMMENT='ADVISORIES: reload OSV for npm+PyPI and rebuild risk. FULL: also refresh registries and dependency graph.'
EXECUTE AS OWNER
AS '
BEGIN
  IF (UPPER(:MODE) = ''FULL'') THEN
    CALL VULN_SENTINEL_DB.RAW.INGEST_REGISTRY(''npm'', 10000);
    CALL VULN_SENTINEL_DB.CORE.MERGE_REGISTRY(''npm'');
    CALL VULN_SENTINEL_DB.RAW.INGEST_REGISTRY(''PyPI'', 15000);
    CALL VULN_SENTINEL_DB.CORE.MERGE_REGISTRY(''PyPI'');
    CALL VULN_SENTINEL_DB.RAW.INGEST_DEPENDENCIES(3, 600);
  END IF;
  CALL VULN_SENTINEL_DB.RAW.INGEST_OSV(''npm'');
  CALL VULN_SENTINEL_DB.CORE.MERGE_OSV(''npm'');
  CALL VULN_SENTINEL_DB.RAW.INGEST_OSV(''PyPI'');
  CALL VULN_SENTINEL_DB.CORE.MERGE_OSV(''PyPI'');
  CREATE OR REPLACE TABLE VULN_SENTINEL_DB.SERVING.PACKAGE_VERSION_RISK AS
  WITH w AS (SELECT ecosystem, name FROM VULN_SENTINEL_DB.CORE.WATCHLIST),
  r AS (
    SELECT a.*, LOWER(a.package_name) pname, d.severity, d.cvss_vector, d.summary, d.cve_ids,
           IFF(a.advisory_id LIKE ''MAL-%'',''MALICIOUS_RELEASE'',''VULNERABILITY'') incident_type
    FROM VULN_SENTINEL_DB.CORE.AFFECTED_RANGES a JOIN VULN_SENTINEL_DB.CORE.ADVISORIES d USING(advisory_id)
    JOIN w ON w.ecosystem=a.ecosystem AND w.name=LOWER(a.package_name)
    WHERE d.withdrawn IS NULL AND COALESCE(d.details,'''') NOT ILIKE ''False positive%''),
  reg AS (
    SELECT pv.ecosystem, LOWER(pv.name) name, pv.version, pv.published_at, pv.yanked, pv.deprecated
    FROM VULN_SENTINEL_DB.CORE.PACKAGE_VERSIONS pv JOIN w ON w.ecosystem=pv.ecosystem AND w.name=LOWER(pv.name)),
  removed AS (
    SELECT DISTINCT r.ecosystem, r.pname name, f.value::string version FROM r, LATERAL FLATTEN(input=>r.affected_versions) f),
  v AS (
    SELECT ecosystem, name, version, published_at, yanked, deprecated, TRUE in_registry FROM reg
    UNION ALL
    SELECT m.ecosystem, m.name, m.version, NULL, NULL, NULL, FALSE FROM removed m
    WHERE NOT EXISTS (SELECT 1 FROM reg WHERE reg.ecosystem=m.ecosystem AND reg.name=m.name AND reg.version=m.version))
  SELECT v.ecosystem, v.name, v.version, v.published_at, v.yanked, v.deprecated, v.in_registry,
         r.advisory_id, r.incident_type, r.severity, r.cvss_vector, r.summary, r.cve_ids, r.fixed
  FROM v JOIN r ON r.ecosystem=v.ecosystem AND r.pname=v.name
  WHERE VULN_SENTINEL_DB.CORE.IS_AFFECTED(v.ecosystem, v.version, r.introduced, r.fixed, r.last_affected, r.affected_versions);
  RETURN ''refreshed: '' || :MODE;
END;
';

CREATE OR REPLACE PROCEDURE VULN_SENTINEL_DB.SERVING.RESPOND("ECOSYSTEM" VARCHAR, "PACKAGE_NAME" VARCHAR, "VERSION" VARCHAR DEFAULT null, "AI_BRIEF" BOOLEAN DEFAULT TRUE)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
ARTIFACT_REPOSITORY = snowflake.snowpark.pypi_shared_repository
PACKAGES = ('snowflake-snowpark-python','packaging')
HANDLER = 'run'
COMMENT='Emergency response for a dependency: affected advisories, blast radius, playbook, recommended safe version, SRE brief'
EXECUTE AS OWNER
AS '
import json, re
from packaging.version import Version, InvalidVersion

SEV = {''CRITICAL'': 4, ''HIGH'': 3, ''MODERATE'': 2, ''LOW'': 1}

def vkey(eco, v):
    try:
        if eco == ''PyPI'':
            pv = Version(v)
            return (0 if pv.is_prerelease or pv.is_devrelease else 1, pv)
        core, _, pre = v.lstrip(''v'').split(''+'')[0].partition(''-'')
        nums = tuple(int(x) if x.isdigit() else 0 for x in (core.split(''.'') + [''0'', ''0''])[:3])
        return (0 if pre else 1, nums)
    except (InvalidVersion, ValueError):
        return None

def major(eco, v):
    k = vkey(eco, v)
    if k is None:
        return None
    return k[1].release[0] if eco == ''PyPI'' else k[1][0]

def q(session, sql, params):
    return [r.as_dict() for r in session.sql(sql, params=params).collect()]

def run(session, ecosystem, package_name, version, ai_brief):
    eco = ''PyPI'' if ecosystem.lower() in (''pypi'', ''pip'', ''python'') else ''npm''
    name = re.sub(r''[-_.]+'', ''-'', package_name).lower() if eco == ''PyPI'' else package_name.lower()

    pkg = q(session, ''''''SELECT p.latest_version, p.monthly_downloads, w.runs_where, w.handles_secrets, w.secret_types, w.demo_reason
        FROM VULN_SENTINEL_DB.CORE.PACKAGES p
        LEFT JOIN VULN_SENTINEL_DB.CORE.WATCHLIST w ON w.ecosystem=p.ecosystem AND w.name=LOWER(p.name)
        WHERE p.ecosystem=? AND LOWER(p.name)=?'''''', [eco, name])
    if not pkg:
        return {''error'': f''{eco}/{name} not found in VULN_SENTINEL_DB.CORE.PACKAGES''}
    pkg = pkg[0]
    version = version or pkg[''LATEST_VERSION'']

    # evaluate directly against ranges so versions removed from the registry still match
    adv = q(session, ''''''SELECT DISTINCT a.advisory_id, IFF(a.advisory_id LIKE ''MAL-%'',''MALICIOUS_RELEASE'',''VULNERABILITY'') incident_type,
          d.severity, d.summary, d.cve_ids, d.aliases, d.published, a.fixed, LEFT(d.details, 1500) details
        FROM VULN_SENTINEL_DB.CORE.AFFECTED_RANGES a JOIN VULN_SENTINEL_DB.CORE.ADVISORIES d USING(advisory_id)
        WHERE a.ecosystem=? AND LOWER(a.package_name)=? AND d.withdrawn IS NULL
          AND COALESCE(d.details,'''') NOT ILIKE ''False positive%''
          AND VULN_SENTINEL_DB.CORE.IS_AFFECTED(a.ecosystem, ?, a.introduced, a.fixed, a.last_affected, a.affected_versions)'''''',
        [eco, name, version])

    reg = q(session, ''''''SELECT version, yanked, deprecated, published_at FROM VULN_SENTINEL_DB.CORE.PACKAGE_VERSIONS
        WHERE ecosystem=? AND LOWER(name)=?'''''', [eco, name])
    in_registry = any(r[''VERSION''] == version for r in reg)
    this = next((r for r in reg if r[''VERSION''] == version), None)

    if any(a[''INCIDENT_TYPE''] == ''MALICIOUS_RELEASE'' for a in adv):
        incident = ''MALICIOUS_RELEASE''
    elif adv:
        incident = ''VULNERABILITY''
    elif not in_registry or (this and (this[''YANKED''] or this[''DEPRECATED''])):
        incident = ''UNAVAILABLE''
    elif name == ''certifi'':
        incident = ''TRUST_STORE''
    else:
        incident = ''NONE''

    # safe version: newest stable, not yanked, not affected by any advisory; prefer same major
    risky = {r[''VERSION''] for r in q(session, ''''''SELECT DISTINCT version FROM VULN_SENTINEL_DB.SERVING.PACKAGE_VERSION_RISK
        WHERE ecosystem=? AND name=?'''''', [eco, name])}
    clean = [r[''VERSION''] for r in reg if not r[''YANKED''] and not r[''DEPRECATED''] and r[''VERSION''] not in risky]
    clean = [v for v in clean if vkey(eco, v) and vkey(eco, v)[0] == 1]
    clean.sort(key=lambda v: vkey(eco, v), reverse=True)
    m = major(eco, version)
    same_major = [v for v in clean if major(eco, v) == m]
    safe = {''same_major'': same_major[0] if same_major else None,
            ''latest_clean'': clean[0] if clean else None}
    if adv and incident == ''VULNERABILITY'':
        fixes = sorted({a[''FIXED''] for a in adv if a[''FIXED'']}, key=lambda v: vkey(eco, v) or (0,))
        safe[''min_fixed_from_advisories''] = fixes[-1] if fixes else None

    blast = q(session, ''''''SELECT dependent, hops, shortest_path, runs_where, handles_secrets, secret_types
        FROM VULN_SENTINEL_DB.SERVING.V_BLAST_RADIUS WHERE ecosystem=? AND compromised=? ORDER BY hops'''''', [eco, name])

    secrets_at_risk = bool(pkg[''HANDLES_SECRETS'']) or any(b[''HANDLES_SECRETS''] for b in blast) or incident == ''MALICIOUS_RELEASE''
    has_fix = bool(safe.get(''same_major'') or safe.get(''latest_clean''))
    steps = q(session, ''''''SELECT step_no, phase, action, owner, automatable, applies_when
        FROM VULN_SENTINEL_DB.SERVING.RESPONSE_PLAYBOOK WHERE incident_type=? ORDER BY step_no'''''', [incident])
    steps = [s for s in steps if s[''APPLIES_WHEN''] == ''always''
             or (s[''APPLIES_WHEN''] == ''handles_secrets'' and secrets_at_risk)
             or (s[''APPLIES_WHEN''] == ''fix_available'' and has_fix)
             or (s[''APPLIES_WHEN''] == ''no_fix'' and not has_fix)]

    adv.sort(key=lambda a: (a[''INCIDENT_TYPE''] != ''MALICIOUS_RELEASE'', -SEV.get(a[''SEVERITY''] or '''', 0)))
    out = {
        ''package'': {''ecosystem'': eco, ''name'': name, ''version'': version, ''in_registry'': in_registry,
                    ''latest_version'': pkg[''LATEST_VERSION''], ''monthly_downloads'': pkg[''MONTHLY_DOWNLOADS''],
                    ''runs_where'': pkg[''RUNS_WHERE''], ''secret_types'': json.loads(pkg[''SECRET_TYPES'']) if pkg[''SECRET_TYPES''] else []},
        ''incident_type'': incident,
        ''advisory_count'': len(adv),
        ''advisories'': [{k.lower(): (str(v) if k == ''PUBLISHED'' else v) for k, v in a.items() if k != ''DETAILS''} for a in adv[:25]],
        ''recommended_version'': safe,
        ''blast_radius'': blast,
        ''secrets_at_risk'': secrets_at_risk,
        ''playbook'': [{k.lower(): v for k, v in s.items() if k != ''APPLIES_WHEN''} for s in steps],
        ''requires_human_approval'': True,
    }

    if ai_brief and incident != ''NONE'':
        ctx = json.dumps({**out, ''top_advisory_details'': [a[''DETAILS''] for a in adv[:3]]}, default=str)[:12000]
        prompt = (''You are an SRE incident lead. Using ONLY the JSON facts below, write a terse incident brief in markdown: ''
                  ''1) one-line verdict, 2) what is affected and why it matters, 3) numbered immediate actions in order, ''
                  ''4) the exact pin/upgrade command for this ecosystem, 5) what a human must approve. ''
                  ''Do not invent versions, CVEs or dates not present in the facts.\\n\\nFACTS:\\n'' + ctx)
        brief = session.sql(''SELECT AI_COMPLETE(?, ?, {\\''temperature\\'': 0, \\''max_tokens\\'': 900})::string b'',
                            params=[''claude-sonnet-4-5'', prompt]).collect()[0][''B'']
        out[''sre_brief''] = brief
    return out
';
