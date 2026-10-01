#!/usr/bin/env python3

import argparse
import csv
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

INPUT_FILE = Path("data/component_repair_candidates.csv")

RAW_EVIDENCE_FILE = Path("evidence_store/registry_evidence_raw.jsonl")
SUMMARY_FILE = Path("data/component_evidence_summary.csv")
LOG_FILE = Path("data/evidence_retrieval_log.csv")

USER_AGENT = "sbom-sha-study/0.1 evidence-retrieval"

SUPPORTED_ECOSYSTEMS = {"npm", "pypi", "maven"}


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def lower(value):
    return clean(value).lower()


def is_missing(value):
    value = clean(value)
    return value == "" or value.lower() in {
        "null",
        "none",
        "unknown",
        "n/a",
        "na",
        "[]",
        "{}",
    }


def request_json(url, timeout=60, retries=2, sleep_between_retries=1.0):
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json",
                },
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                return json.loads(body)

        except TimeoutError as e:
            last_error = e
            if attempt < retries:
                time.sleep(sleep_between_retries)
            else:
                raise

        except urllib.error.URLError as e:
            last_error = e
            if attempt < retries:
                time.sleep(sleep_between_retries)
            else:
                raise

    raise last_error


def request_text(url, timeout=60, retries=2, sleep_between_retries=1.0):
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/xml,text/xml,text/plain,*/*",
                },
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")

        except TimeoutError as e:
            last_error = e
            if attempt < retries:
                time.sleep(sleep_between_retries)
            else:
                raise

        except urllib.error.URLError as e:
            last_error = e
            if attempt < retries:
                time.sleep(sleep_between_retries)
            else:
                raise

    raise last_error


def parse_purl(row):
    purl = clean(row.get("purl"))

    result = {
        "type": "",
        "namespace": "",
        "name": clean(row.get("name")),
        "version": clean(row.get("version")),
    }

    if not purl.startswith("pkg:"):
        return result

    without_prefix = purl[len("pkg:") :]

    if "/" not in without_prefix:
        return result

    purl_type, rest = without_prefix.split("/", 1)
    purl_type = purl_type.lower()
    result["type"] = purl_type

    if "?" in rest:
        rest = rest.split("?", 1)[0]

    # Use rsplit because scoped npm packages contain @ in the package name.
    if "@" in rest:
        path_part, version = rest.rsplit("@", 1)
        result["version"] = urllib.parse.unquote(version)
    else:
        path_part = rest

    path_part = urllib.parse.unquote(path_part)

    parts = path_part.split("/")

    if purl_type == "maven":
        if len(parts) >= 2:
            result["namespace"] = "/".join(parts[:-1])
            result["name"] = parts[-1]
        elif len(parts) == 1:
            result["name"] = parts[0]

    elif purl_type == "npm":
        result["name"] = path_part

    elif purl_type == "pypi":
        result["name"] = path_part

    else:
        result["name"] = path_part

    return result


def infer_coordinates(row):
    parsed = parse_purl(row)

    purl_type = clean(parsed.get("type")).lower()

    # `ecosystem_normalized` is the component-level ecosystem produced by
    # classify_repair_eligibility.py. `project_ecosystem_label` preserves the
    # repository/project-level label for analysis only.
    normalized_ecosystem = lower(row.get("ecosystem_normalized"))
    project_ecosystem = lower(row.get("project_ecosystem_label")) or lower(
        row.get("ecosystem")
    )

    # Component PURL is authoritative for selecting a registry adapter.
    if purl_type in SUPPORTED_ECOSYSTEMS:
        ecosystem = purl_type
    elif normalized_ecosystem:
        ecosystem = normalized_ecosystem
    else:
        ecosystem = project_ecosystem

    name = parsed["name"] or clean(row.get("name"))
    version = parsed["version"] or clean(row.get("version"))
    namespace = parsed["namespace"] or clean(row.get("group"))

    # For actual Maven components, CSV group/name/version can contain the
    # clearest GAV coordinates. Never let a Maven project label override a
    # non-Maven PURL.
    if ecosystem == "maven" and purl_type in {"", "maven"}:
        csv_group = clean(row.get("group"))
        csv_name = clean(row.get("name"))
        csv_version = clean(row.get("version"))

        if csv_group:
            namespace = csv_group
        if csv_name:
            name = csv_name
        if csv_version:
            version = csv_version

    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "namespace": namespace,
        "purl_type": purl_type,
        "project_ecosystem": project_ecosystem,
    }


def normalize_repository_url(value):
    if not value:
        return ""

    if isinstance(value, dict):
        url = clean(value.get("url"))
    else:
        url = clean(value)

    if url.startswith("git+"):
        url = url[len("git+") :]

    if url.endswith(".git"):
        url = url[:-4]

    return url


def first_nonempty(*values):
    for value in values:
        value = clean(value)
        if value:
            return value
    return ""



def split_semicolon_fields(value):
    return {
        item.strip()
        for item in clean(value).split(";")
        if item.strip() and item.strip() != "none"
    }


def field_is_auto_target(row, field):
    return field in split_semicolon_fields(row.get("target_fields_predicted"))


def field_is_manual_review(row, field):
    return field in split_semicolon_fields(row.get("manual_review_fields_predicted"))


def canonical_artifact_url(value):
    """Canonicalize a URL for strict artifact matching.

    Query strings and fragments are ignored because they may contain mirrors,
    cache keys, or signatures; scheme/host/path must still identify the same
    artifact endpoint.
    """
    value = clean(value)
    if not value:
        return ""

    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return ""

    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return ""

    path = urllib.parse.unquote(parts.path or "")
    return urllib.parse.urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), path, "", "")
    )


def artifact_urls_match(left, right):
    left_c = canonical_artifact_url(left)
    right_c = canonical_artifact_url(right)
    return bool(left_c and right_c and left_c == right_c)


def artifact_filename(value):
    canonical = canonical_artifact_url(value)
    if not canonical:
        return ""
    return Path(urllib.parse.urlsplit(canonical).path).name


def hash_auto_requested(row):
    return (
        field_is_auto_target(row, "hash_values")
        and clean(row.get("artifact_identity_status_predicted"))
        == "exact_artifact_url_present"
        and not is_missing(row.get("distribution_url"))
    )


def empty_artifact_result(row, status):
    return {
        "input_artifact_url": clean(row.get("distribution_url")),
        "artifact_url": "",
        "artifact_filename": artifact_filename(row.get("distribution_url")),
        "artifact_match": False,
        "artifact_match_method": "none",
        "hash_usable_for_auto_repair": False,
        "hash_status": status,
        "hash_algorithms": [],
        "hash_values": [],
    }


def exact_registry_artifact_result(row, registry_artifact_url, hash_pairs):
    """Return hash metadata only when the registry artifact is the SBOM artifact."""
    input_url = clean(row.get("distribution_url"))

    if not hash_auto_requested(row):
        return empty_artifact_result(row, "hash_not_auto_targeted")

    if not artifact_urls_match(input_url, registry_artifact_url):
        return empty_artifact_result(row, "exact_artifact_not_matched")

    algorithms = []
    values = []
    for algorithm, value in hash_pairs:
        algorithm = clean(algorithm)
        value = clean(value)
        if algorithm and value:
            algorithms.append(algorithm)
            values.append(value)

    if not values:
        result = empty_artifact_result(row, "exact_artifact_matched_but_hash_unavailable")
        result.update(
            {
                "artifact_url": clean(registry_artifact_url),
                "artifact_filename": artifact_filename(registry_artifact_url),
                "artifact_match": True,
                "artifact_match_method": "exact_url",
            }
        )
        return result

    return {
        "input_artifact_url": input_url,
        "artifact_url": clean(registry_artifact_url),
        "artifact_filename": artifact_filename(registry_artifact_url),
        "artifact_match": True,
        "artifact_match_method": "exact_url",
        "hash_usable_for_auto_repair": True,
        "hash_status": "exact_artifact_hash_available",
        "hash_algorithms": algorithms,
        "hash_values": values,
    }


def select_default_pypi_distribution(urls):
    """Choose a deterministic distribution URL for the non-hash field.

    This choice is not used to justify a hash. Hashes require an exact match to
    the artifact URL already present in the original SBOM.
    """
    if not urls:
        return None

    sdists = [item for item in urls if lower(item.get("packagetype")) == "sdist"]
    pool = sdists if sdists else list(urls)
    return sorted(pool, key=lambda item: clean(item.get("filename")))[0]


def find_exact_pypi_artifact(urls, input_artifact_url):
    for item in urls:
        registry_url = clean(item.get("url"))
        if artifact_urls_match(input_artifact_url, registry_url):
            return item
    return None


def validate_maven_artifact_url(url, group_id, artifact_id, version):
    """Require the explicit artifact URL to belong to the exact Maven GAV path."""
    canonical = canonical_artifact_url(url)
    if not canonical:
        return False

    parts = urllib.parse.urlsplit(canonical)
    if parts.netloc not in {"repo1.maven.org", "repo.maven.apache.org"}:
        return False

    group_path = maven_group_to_path(group_id).strip("/")
    expected_dir = f"/maven2/{group_path}/{artifact_id}/{version}/"
    if not parts.path.startswith(expected_dir):
        return False

    filename = Path(parts.path).name
    expected_prefix = f"{artifact_id}-{version}"
    if not filename.startswith(expected_prefix):
        return False

    # The classifier already requires a concrete artifact suffix. Repeat a
    # conservative check here as a second safety layer.
    lower_name = filename.lower()
    allowed_suffixes = (
        ".jar",
        ".war",
        ".ear",
        ".zip",
        ".tgz",
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
    )
    return lower_name.endswith(allowed_suffixes)


def clean_party_value(value):
    """Convert common registry party representations into readable text."""

    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    if isinstance(value, dict):
        name = clean(value.get("name"))
        email = clean(value.get("email"))

        if name and email:
            return f"{name} <{email}>"

        return name or email

    return clean(value)


def add_party_candidate(candidates, value, role, source_field):
    """Add a registry-derived party candidate while preserving its role."""

    cleaned = clean_party_value(value)

    if not cleaned:
        return

    candidate = {
        "value": cleaned,
        "role": clean(role),
        "source_field": clean(source_field),
    }

    duplicate = any(
        existing.get("value", "").casefold() == cleaned.casefold()
        and existing.get("role", "") == candidate["role"]
        and existing.get("source_field", "") == candidate["source_field"]
        for existing in candidates
    )

    if not duplicate:
        candidates.append(candidate)


def party_values_equivalent(left, right):
    """Compare party values while tolerating a trailing email representation."""

    left_clean = clean_party_value(left)
    right_clean = clean_party_value(right)

    if not left_clean or not right_clean:
        return False

    if left_clean.casefold() == right_clean.casefold():
        return True

    def name_only(value):
        value = re.sub(r"\s*<[^>]+>\s*$", "", value).strip()
        return value

    return name_only(left_clean).casefold() == name_only(right_clean).casefold()


def match_selected_party(selected_value, candidates):
    """Locate the role/source that produced the selected supplier-like value."""

    selected = clean_party_value(selected_value)

    if not selected:
        return {
            "party_value": "",
            "party_role": "",
            "party_source_field": "",
            "party_candidates": candidates,
        }

    exact_matches = [
        candidate
        for candidate in candidates
        if party_values_equivalent(candidate.get("value", ""), selected)
    ]

    if exact_matches:
        match = exact_matches[0]
        return {
            "party_value": selected,
            "party_role": match.get("role", ""),
            "party_source_field": match.get("source_field", ""),
            "party_candidates": candidates,
        }

    return {
        "party_value": selected,
        "party_role": "unknown",
        "party_source_field": "not_preserved",
        "party_candidates": candidates,
    }


def lookup_npm(row):
    coords = infer_coordinates(row)
    package_name = coords["name"]
    version = coords["version"]

    if is_missing(package_name):
        raise ValueError("Missing npm package name")

    encoded_name = urllib.parse.quote(package_name, safe="")
    url = f"https://registry.npmjs.org/{encoded_name}"

    data = request_json(url)

    versions = data.get("versions", {})
    version_data = versions.get(version, {}) if version else {}
    exact_version_match = bool(version_data)

    # Never substitute latest metadata for a requested version.
    if not version_data:
        version_data = {}

    license_value = first_nonempty(
        version_data.get("license", ""),
        data.get("license", ""),
    )

    version_repository = version_data.get("repository", "")
    package_repository = data.get("repository", "")

    repository_url = normalize_repository_url(
        first_nonempty(
            version_repository.get("url", "")
            if isinstance(version_repository, dict)
            else version_repository,
            package_repository.get("url", "")
            if isinstance(package_repository, dict)
            else package_repository,
        )
    )

    dist = (
        version_data.get("dist", {})
        if isinstance(version_data.get("dist", {}), dict)
        else {}
    )

    distribution_url = clean(dist.get("tarball"))
    integrity = clean(dist.get("integrity"))
    shasum = clean(dist.get("shasum"))

    # A registry hash becomes repairable only when its canonical tarball is
    # exactly the artifact URL already identified in the original SBOM.
    artifact_result = exact_registry_artifact_result(
        row,
        distribution_url,
        [("integrity", integrity), ("sha1", shasum)],
    )

    party_candidates = []

    add_party_candidate(
        party_candidates,
        version_data.get("author"),
        "author",
        "npm.version.author",
    )
    add_party_candidate(
        party_candidates,
        data.get("author"),
        "author",
        "npm.package.author",
    )

    for maintainer in version_data.get("maintainers") or []:
        add_party_candidate(
            party_candidates,
            maintainer,
            "maintainer",
            "npm.version.maintainers",
        )

    for maintainer in data.get("maintainers") or []:
        add_party_candidate(
            party_candidates,
            maintainer,
            "maintainer",
            "npm.package.maintainers",
        )

    add_party_candidate(
        party_candidates,
        version_data.get("_npmUser"),
        "publisher_account",
        "npm.version._npmUser",
    )

    if package_name.startswith("@") and "/" in package_name:
        npm_scope = package_name.split("/", 1)[0]
        add_party_candidate(
            party_candidates,
            npm_scope,
            "npm_scope",
            "npm.package.name",
        )

    supplier = ""

    # Preserve the historical party candidate for downstream semantic
    # validation. It must not be treated as a CycloneDX supplier merely because
    # it is an author, maintainer, publisher account, or scope.
    if package_name.startswith("@") and "/" in package_name:
        supplier = package_name.split("/", 1)[0]

    if not supplier:
        author = version_data.get("author") or data.get("author")
        supplier = clean_party_value(author)

    if not supplier:
        maintainers = version_data.get("maintainers") or data.get("maintainers") or []
        if maintainers and isinstance(maintainers, list):
            supplier = clean_party_value(maintainers[0])

    party_provenance = match_selected_party(supplier, party_candidates)

    return {
        "source": "npm_registry",
        "package_name": package_name,
        "version": version,
        "exact_version_match": exact_version_match,
        "registry_url": url,
        "license": license_value,
        "repository_url": repository_url,
        "supplier": supplier,
        "party_value": party_provenance["party_value"],
        "party_role": party_provenance["party_role"],
        "party_source_field": party_provenance["party_source_field"],
        "party_candidates": party_provenance["party_candidates"],
        "distribution_url": distribution_url,
        "input_artifact_url": artifact_result["input_artifact_url"],
        "artifact_url": artifact_result["artifact_url"],
        "artifact_filename": artifact_result["artifact_filename"],
        "artifact_match": artifact_result["artifact_match"],
        "artifact_match_method": artifact_result["artifact_match_method"],
        "hash_usable_for_auto_repair": artifact_result["hash_usable_for_auto_repair"],
        "hash_status": artifact_result["hash_status"],
        "hash_algorithms": artifact_result["hash_algorithms"],
        "hash_values": artifact_result["hash_values"],
        "raw_package_metadata_keys": sorted(list(data.keys())),
    }


def lookup_pypi(row):
    coords = infer_coordinates(row)
    package_name = coords["name"]
    version = coords["version"]

    if is_missing(package_name):
        raise ValueError("Missing PyPI package name")

    encoded_name = urllib.parse.quote(package_name, safe="")
    url = f"https://pypi.org/pypi/{encoded_name}/json"

    data = request_json(url)

    info = data.get("info", {})
    releases = data.get("releases", {})

    exact_version_match = bool(version and version in releases)
    urls = releases.get(version, []) or [] if exact_version_match else []

    license_value = first_nonempty(info.get("license", ""))

    if not license_value:
        classifiers = info.get("classifiers", []) or []
        license_classifiers = [
            classifier
            for classifier in classifiers
            if classifier.lower().startswith("license ::")
        ]
        if license_classifiers:
            license_value = "; ".join(license_classifiers)

    # Strict repository semantics: only explicit source/repository/code labels
    # are considered repository URLs. Homepage and bug-tracker URLs are not
    # silently reinterpreted as source repositories.
    project_urls = info.get("project_urls") or {}
    repository_url = ""

    if isinstance(project_urls, dict):
        preferred_labels = ["source", "source code", "repository", "code"]
        normalized_project_urls = {
            lower(key): clean(value)
            for key, value in project_urls.items()
            if clean(value)
        }
        for label in preferred_labels:
            if label in normalized_project_urls:
                repository_url = normalized_project_urls[label]
                break

    repository_url = normalize_repository_url(repository_url)

    party_candidates = []
    add_party_candidate(
        party_candidates,
        info.get("author"),
        "author",
        "pypi.info.author",
    )
    add_party_candidate(
        party_candidates,
        info.get("author_email"),
        "author_email",
        "pypi.info.author_email",
    )
    add_party_candidate(
        party_candidates,
        info.get("maintainer"),
        "maintainer",
        "pypi.info.maintainer",
    )
    add_party_candidate(
        party_candidates,
        info.get("maintainer_email"),
        "maintainer_email",
        "pypi.info.maintainer_email",
    )

    supplier = first_nonempty(
        info.get("maintainer", ""),
        info.get("author", ""),
        info.get("maintainer_email", ""),
        info.get("author_email", ""),
    )
    party_provenance = match_selected_party(supplier, party_candidates)

    input_artifact_url = clean(row.get("distribution_url"))
    exact_artifact = (
        find_exact_pypi_artifact(urls, input_artifact_url)
        if exact_version_match and input_artifact_url
        else None
    )

    # Distribution URL retrieval is independent of hash repair. If the SBOM
    # already identifies an exact artifact and PyPI confirms it, preserve that
    # same URL. Otherwise choose a deterministic release distribution for the
    # distribution_url field only.
    selected_distribution = exact_artifact or select_default_pypi_distribution(urls)
    distribution_url = clean(selected_distribution.get("url")) if selected_distribution else ""

    artifact_result = empty_artifact_result(row, "hash_not_auto_targeted")

    if hash_auto_requested(row):
        if not exact_version_match:
            artifact_result = empty_artifact_result(row, "exact_version_not_matched")
        elif exact_artifact is None:
            artifact_result = empty_artifact_result(row, "exact_artifact_not_matched")
        else:
            digests = exact_artifact.get("digests") or {}
            hash_pairs = [
                (algorithm, value)
                for algorithm, value in digests.items()
                if value
            ]
            artifact_result = exact_registry_artifact_result(
                row,
                clean(exact_artifact.get("url")),
                hash_pairs,
            )

    return {
        "source": "pypi_registry",
        "package_name": package_name,
        "version": version,
        "exact_version_match": exact_version_match,
        "registry_url": url,
        "license": license_value,
        "repository_url": repository_url,
        "supplier": supplier,
        "party_value": party_provenance["party_value"],
        "party_role": party_provenance["party_role"],
        "party_source_field": party_provenance["party_source_field"],
        "party_candidates": party_provenance["party_candidates"],
        "distribution_url": distribution_url,
        "input_artifact_url": artifact_result["input_artifact_url"],
        "artifact_url": artifact_result["artifact_url"],
        "artifact_filename": artifact_result["artifact_filename"],
        "artifact_match": artifact_result["artifact_match"],
        "artifact_match_method": artifact_result["artifact_match_method"],
        "hash_usable_for_auto_repair": artifact_result["hash_usable_for_auto_repair"],
        "hash_status": artifact_result["hash_status"],
        "hash_algorithms": artifact_result["hash_algorithms"],
        "hash_values": artifact_result["hash_values"],
        "raw_info_keys": sorted(list(info.keys())),
    }


def maven_group_to_path(group_id):
    return group_id.replace(".", "/")


def parse_maven_pom(pom_text):
    result = {
        "license": "",
        "repository_url": "",
        "supplier": "",
        "party_value": "",
        "party_role": "",
        "party_source_field": "",
        "party_candidates": [],
    }

    try:
        root = ET.fromstring(pom_text)
    except ET.ParseError:
        return result

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0] + "}"

    def find_text(path):
        elem = root.find(path)
        if elem is not None and elem.text:
            return elem.text.strip()
        return ""

    licenses = root.findall(f".//{ns}licenses/{ns}license")
    license_names = []

    for license_element in licenses:
        name_element = license_element.find(f"{ns}name")
        if name_element is not None and name_element.text:
            license_names.append(name_element.text.strip())

    if license_names:
        result["license"] = "; ".join(license_names)

    scm_url = first_nonempty(
        find_text(f"{ns}scm/{ns}url"),
        find_text(f"{ns}scm/{ns}connection"),
        find_text(f"{ns}scm/{ns}developerConnection"),
    )

    if scm_url.startswith("scm:"):
        parts = scm_url.split(":")
        for index, part in enumerate(parts):
            if part in {"http", "https"} and index + 1 < len(parts):
                scm_url = ":".join(parts[index:])
                break
            if part.startswith("http"):
                scm_url = part
                break

    result["repository_url"] = normalize_repository_url(
        first_nonempty(scm_url, find_text(f"{ns}url"))
    )

    party_candidates = []

    organization_name = find_text(f"{ns}organization/{ns}name")
    add_party_candidate(
        party_candidates,
        organization_name,
        "organization",
        "maven.pom.organization.name",
    )

    developers = root.findall(f".//{ns}developers/{ns}developer")
    for developer in developers:
        name_element = developer.find(f"{ns}name")
        organization_element = developer.find(f"{ns}organization")

        developer_name = (
            name_element.text.strip()
            if name_element is not None and name_element.text
            else ""
        )
        developer_organization = (
            organization_element.text.strip()
            if organization_element is not None and organization_element.text
            else ""
        )

        add_party_candidate(
            party_candidates,
            developer_name,
            "developer",
            "maven.pom.developers.developer.name",
        )
        add_party_candidate(
            party_candidates,
            developer_organization,
            "developer_organization",
            "maven.pom.developers.developer.organization",
        )

    supplier = first_nonempty(
        organization_name,
        next(
            (
                candidate["value"]
                for candidate in party_candidates
                if candidate["role"] == "developer_organization"
            ),
            "",
        ),
        next(
            (
                candidate["value"]
                for candidate in party_candidates
                if candidate["role"] == "developer"
            ),
            "",
        ),
    )

    party_provenance = match_selected_party(supplier, party_candidates)

    result["supplier"] = supplier
    result["party_value"] = party_provenance["party_value"]
    result["party_role"] = party_provenance["party_role"]
    result["party_source_field"] = party_provenance["party_source_field"]
    result["party_candidates"] = party_provenance["party_candidates"]

    return result


def lookup_maven(row):
    coords = infer_coordinates(row)

    group_id = coords["namespace"] or clean(row.get("group"))
    artifact_id = coords["name"]
    version = coords["version"]

    if is_missing(group_id) or is_missing(artifact_id) or is_missing(version):
        raise ValueError("Missing Maven group/artifact/version")

    query = f'g:"{group_id}" AND a:"{artifact_id}" AND v:"{version}"'
    encoded_query = urllib.parse.quote(query, safe="")
    search_url = (
        "https://search.maven.org/solrsearch/select"
        f"?q={encoded_query}&rows=20&wt=json"
    )

    docs = []
    search_status = "not_attempted"

    try:
        search_data = request_json(search_url, timeout=60, retries=2)
        docs = search_data.get("response", {}).get("docs", [])
        search_status = "success"
    except urllib.error.HTTPError as e:
        search_status = f"http_error: {e.code} {e.reason}"
    except TimeoutError as e:
        search_status = f"timeout: {e}"
    except Exception as e:
        search_status = f"error: {type(e).__name__}: {e}"

    exact_version_match = len(docs) > 0

    base_repo_url = (
        "https://repo1.maven.org/maven2/"
        f"{maven_group_to_path(group_id)}/{artifact_id}/{version}"
    )

    pom_url = f"{base_repo_url}/{artifact_id}-{version}.pom"
    default_jar_url = f"{base_repo_url}/{artifact_id}-{version}.jar"

    pom_evidence = {
        "license": "",
        "repository_url": "",
        "supplier": "",
        "party_value": "",
        "party_role": "",
        "party_source_field": "",
        "party_candidates": [],
    }

    pom_status = "not_attempted"

    try:
        pom_text = request_text(pom_url, timeout=60, retries=2)
        pom_status = "found"
        pom_evidence = parse_maven_pom(pom_text)
    except urllib.error.HTTPError as e:
        pom_status = f"http_error: {e.code} {e.reason}"
    except TimeoutError as e:
        pom_status = f"timeout: {e}"
    except Exception as e:
        pom_status = f"error: {type(e).__name__}: {e}"

    # Hashes are never taken from an assumed default JAR. They are retrieved
    # only for the concrete Maven Central artifact URL already present in the
    # original SBOM and validated against the exact GAV directory.
    artifact_result = empty_artifact_result(row, "hash_not_auto_targeted")
    checksum_status = "not_attempted"

    if hash_auto_requested(row):
        input_artifact_url = clean(row.get("distribution_url"))

        if not exact_version_match:
            artifact_result = empty_artifact_result(row, "exact_version_not_matched")
        elif not validate_maven_artifact_url(
            input_artifact_url, group_id, artifact_id, version
        ):
            artifact_result = empty_artifact_result(row, "exact_artifact_not_matched_to_gav")
        else:
            hash_pairs = []
            checksum_attempts = []

            for algorithm, suffix in (("sha256", ".sha256"), ("sha1", ".sha1")):
                checksum_url = canonical_artifact_url(input_artifact_url) + suffix
                try:
                    value = request_text(
                        checksum_url, timeout=60, retries=2
                    ).strip().split()[0]
                    if value:
                        hash_pairs.append((algorithm, value))
                        checksum_attempts.append(f"{algorithm}:found")
                    else:
                        checksum_attempts.append(f"{algorithm}:empty")
                except urllib.error.HTTPError as e:
                    checksum_attempts.append(f"{algorithm}:http_{e.code}")
                except TimeoutError:
                    checksum_attempts.append(f"{algorithm}:timeout")
                except Exception as e:
                    checksum_attempts.append(f"{algorithm}:error_{type(e).__name__}")

            checksum_status = ";".join(checksum_attempts) or "not_attempted"
            artifact_result = exact_registry_artifact_result(
                row,
                input_artifact_url,
                hash_pairs,
            )

    return {
        "source": "maven_central",
        "group_id": group_id,
        "artifact_id": artifact_id,
        "package_name": f"{group_id}:{artifact_id}",
        "version": version,
        "exact_version_match": exact_version_match,
        "registry_url": search_url,
        "search_status": search_status,
        "pom_url": pom_url,
        "pom_status": pom_status,
        "license": pom_evidence.get("license", ""),
        "repository_url": pom_evidence.get("repository_url", ""),
        "supplier": pom_evidence.get("supplier", ""),
        "party_value": pom_evidence.get("party_value", ""),
        "party_role": pom_evidence.get("party_role", ""),
        "party_source_field": pom_evidence.get("party_source_field", ""),
        "party_candidates": pom_evidence.get("party_candidates", []),
        "distribution_url": default_jar_url if exact_version_match else "",
        "input_artifact_url": artifact_result["input_artifact_url"],
        "artifact_url": artifact_result["artifact_url"],
        "artifact_filename": artifact_result["artifact_filename"],
        "artifact_match": artifact_result["artifact_match"],
        "artifact_match_method": artifact_result["artifact_match_method"],
        "hash_usable_for_auto_repair": artifact_result["hash_usable_for_auto_repair"],
        "hash_status": artifact_result["hash_status"],
        "hash_algorithms": artifact_result["hash_algorithms"],
        "hash_values": artifact_result["hash_values"],
        "checksum_status": checksum_status,
        "maven_search_docs_count": len(docs),
    }


def evidence_confidence(evidence):
    if not evidence:
        return "none"

    source = evidence.get("source", "")

    if not evidence.get("exact_version_match"):
        return "low"

    if source == "maven_central":
        pom_status = evidence.get("pom_status", "")
        if pom_status == "found":
            return "high"
        return "medium"

    if source in {"npm_registry", "pypi_registry"}:
        return "high"

    return "medium"


def load_candidates(limit_per_ecosystem=None):
    rows = []

    with INPUT_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        counts = Counter()

        for row in reader:
            decision = clean(row.get("repair_decision_predicted"))

            if decision != "auto_repair_candidate":
                continue

            coords = infer_coordinates(row)
            component_ecosystem = coords["ecosystem"]

            if component_ecosystem not in SUPPORTED_ECOSYSTEMS:
                continue

            if limit_per_ecosystem is not None:
                if counts[component_ecosystem] >= limit_per_ecosystem:
                    continue
                counts[component_ecosystem] += 1

            row["retrieval_ecosystem"] = component_ecosystem
            rows.append(row)

    return rows


def write_csv(path, rows):
    if not rows:
        with path.open("w", newline="", encoding="utf-8") as f:
            f.write("")
        return

    fieldnames = list(rows[0].keys())

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Retrieve registry metadata for SHM auto-repair candidates."
    )
    parser.add_argument(
        "--limit-per-ecosystem",
        type=int,
        default=50,
        help="Maximum candidates per component ecosystem. Use 0 for full run.",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.2,
        help="Sleep seconds between registry requests.",
    )

    args = parser.parse_args()

    limit = None if args.limit_per_ecosystem == 0 else args.limit_per_ecosystem

    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Missing input file: {INPUT_FILE}")

    candidates = load_candidates(limit_per_ecosystem=limit)

    print(f"Loaded auto-repair candidates for metadata retrieval: {len(candidates)}")

    RAW_EVIDENCE_FILE.parent.mkdir(parents=True, exist_ok=True)

    summary_rows = []
    log_rows = []

    with RAW_EVIDENCE_FILE.open("w", encoding="utf-8") as raw_out:
        for index, row in enumerate(candidates, start=1):
            component_id = clean(row.get("component_id"))

            coords = infer_coordinates(row)
            ecosystem = coords["ecosystem"]
            project_ecosystem = coords["project_ecosystem"]
            purl_type = coords["purl_type"]

            status = "success"
            error_message = ""
            evidence = {}

            try:
                if ecosystem == "npm":
                    evidence = lookup_npm(row)
                elif ecosystem == "pypi":
                    evidence = lookup_pypi(row)
                elif ecosystem == "maven":
                    evidence = lookup_maven(row)
                else:
                    raise ValueError(f"Unsupported ecosystem: {ecosystem}")

            except urllib.error.HTTPError as e:
                status = "http_error"
                error_message = f"{e.code} {e.reason}"
            except urllib.error.URLError as e:
                status = "url_error"
                error_message = str(e.reason)
            except TimeoutError as e:
                status = "timeout"
                error_message = str(e)
            except Exception as e:
                status = "error"
                error_message = f"{type(e).__name__}: {e}"

            retrieved_at = now_utc()

            raw_record = {
                "component_id": component_id,
                "project_id": clean(row.get("project_id")),
                "ecosystem": ecosystem,
                "project_ecosystem": project_ecosystem,
                "purl_type": purl_type,
                "tool": clean(row.get("tool")),
                "sbom_path": clean(row.get("sbom_path")),
                "component_index": clean(row.get("component_index")),
                "name": clean(row.get("name")),
                "version": clean(row.get("version")),
                "purl": clean(row.get("purl")),
                "target_fields_predicted": clean(row.get("target_fields_predicted")),
                "manual_review_fields_predicted": clean(row.get("manual_review_fields_predicted")),
                "artifact_identity_status_predicted": clean(row.get("artifact_identity_status_predicted")),
                "status": status,
                "error_message": error_message,
                "retrieved_at": retrieved_at,
                "evidence": evidence,
            }

            raw_out.write(json.dumps(raw_record, ensure_ascii=False) + "\n")

            confidence = evidence_confidence(evidence) if status == "success" else "none"

            summary_rows.append(
                {
                    "component_id": component_id,
                    "project_id": clean(row.get("project_id")),
                    "ecosystem": ecosystem,
                    "project_ecosystem": project_ecosystem,
                    "purl_type": purl_type,
                    "tool": clean(row.get("tool")),
                    "sbom_path": clean(row.get("sbom_path")),
                    "component_index": clean(row.get("component_index")),
                    "name": clean(row.get("name")),
                    "version": clean(row.get("version")),
                    "purl": clean(row.get("purl")),
                    "target_fields_predicted": clean(row.get("target_fields_predicted")),
                    "manual_review_fields_predicted": clean(row.get("manual_review_fields_predicted")),
                    "artifact_identity_status_predicted": clean(row.get("artifact_identity_status_predicted")),
                    "evidence_status": status,
                    "evidence_source": evidence.get("source", ""),
                    "evidence_exact_version_match": evidence.get("exact_version_match", ""),
                    "evidence_package_name": evidence.get("package_name", ""),
                    "evidence_registry_url": evidence.get("registry_url", ""),
                    "evidence_license": evidence.get("license", ""),
                    "evidence_repository_url": evidence.get("repository_url", ""),
                    "evidence_supplier": evidence.get("supplier", ""),
                    "evidence_party_value": evidence.get("party_value", ""),
                    "evidence_party_role": evidence.get("party_role", ""),
                    "evidence_party_source_field": evidence.get("party_source_field", ""),
                    "evidence_party_candidates_json": json.dumps(
                        evidence.get("party_candidates", []),
                        ensure_ascii=False,
                    ),
                    "evidence_distribution_url": evidence.get("distribution_url", ""),
                    "evidence_input_artifact_url": evidence.get("input_artifact_url", ""),
                    "evidence_artifact_url": evidence.get("artifact_url", ""),
                    "evidence_artifact_filename": evidence.get("artifact_filename", ""),
                    "evidence_artifact_match": evidence.get("artifact_match", False),
                    "evidence_artifact_match_method": evidence.get("artifact_match_method", ""),
                    "evidence_hash_usable_for_auto_repair": evidence.get(
                        "hash_usable_for_auto_repair", False
                    ),
                    "evidence_hash_status": evidence.get("hash_status", ""),
                    "evidence_hash_algorithms": ";".join(evidence.get("hash_algorithms", [])),
                    "evidence_hash_values": ";".join(evidence.get("hash_values", [])),
                    "evidence_confidence": confidence,
                    "evidence_error": error_message,
                    "retrieved_at": retrieved_at,
                }
            )

            log_rows.append(
                {
                    "component_id": component_id,
                    "project_ecosystem": project_ecosystem,
                    "ecosystem": ecosystem,
                    "purl_type": purl_type,
                    "name": clean(row.get("name")),
                    "version": clean(row.get("version")),
                    "purl": clean(row.get("purl")),
                    "target_fields_predicted": clean(row.get("target_fields_predicted")),
                    "manual_review_fields_predicted": clean(row.get("manual_review_fields_predicted")),
                    "hash_status": evidence.get("hash_status", "") if evidence else "",
                    "artifact_match": evidence.get("artifact_match", False) if evidence else False,
                    "status": status,
                    "error_message": error_message,
                    "retrieved_at": retrieved_at,
                }
            )

            if index % 25 == 0:
                print(f"Processed {index}/{len(candidates)}")

            if args.sleep > 0:
                time.sleep(args.sleep)

    write_csv(SUMMARY_FILE, summary_rows)
    write_csv(LOG_FILE, log_rows)

    print(f"Saved raw evidence to: {RAW_EVIDENCE_FILE}")
    print(f"Saved evidence summary to: {SUMMARY_FILE}")
    print(f"Saved retrieval log to: {LOG_FILE}")

    print("\nRetrieval status summary:")
    for status, count in Counter(row["evidence_status"] for row in summary_rows).most_common():
        print(f"{status}: {count}")

    print("\nRetrieval ecosystem summary:")
    for ecosystem, count in Counter(row["ecosystem"] for row in summary_rows).most_common():
        print(f"{ecosystem}: {count}")


if __name__ == "__main__":
    main()