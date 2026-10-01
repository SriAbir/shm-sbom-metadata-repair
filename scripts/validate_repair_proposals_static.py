#!/usr/bin/env python3

import base64
import csv
import re
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROVENANCE_FILE = Path("data/component_repair_provenance.csv")
EVIDENCE_FILE = Path("data/component_evidence_summary.csv")

OUTPUT_ALL = Path("data/static_validation_all_repairs.csv")
OUTPUT_REVIEW_QUEUE = Path("data/static_validation_review_queue.csv")
OUTPUT_SUMMARY = Path("data/static_validation_summary.csv")
OUTPUT_BY_FIELD = Path("data/static_validation_summary_by_field.csv")
OUTPUT_BY_ECOSYSTEM = Path(
    "data/static_validation_summary_by_ecosystem.csv"
)

# Evidence fields copied into the static-validation output so the next
# semantic-validation stage can consume the same occurrence-level record
# without performing a weaker component-only join.
EVIDENCE_CONTEXT_COLUMNS = [
    "evidence_status",
    "evidence_source",
    "evidence_exact_version_match",
    "evidence_package_name",
    "evidence_registry_url",
    "evidence_license",
    "evidence_repository_url",
    "evidence_supplier",
    "evidence_party_value",
    "evidence_party_role",
    "evidence_party_source_field",
    "evidence_party_candidates_json",
    "evidence_distribution_url",
    "evidence_input_artifact_url",
    "evidence_artifact_url",
    "evidence_artifact_filename",
    "evidence_artifact_match",
    "evidence_artifact_match_method",
    "evidence_hash_usable_for_auto_repair",
    "evidence_hash_status",
    "evidence_hash_algorithms",
    "evidence_hash_values",
    "evidence_confidence",
    "evidence_error",
    "retrieved_at",
]

MISSING_VALUES = {
    "",
    "null",
    "none",
    "unknown",
    "n/a",
    "na",
    "[]",
    "{}",
}

KNOWN_VCS_HOSTS = {
    "github.com",
    "www.github.com",
    "gitlab.com",
    "www.gitlab.com",
    "bitbucket.org",
    "www.bitbucket.org",
    "codeberg.org",
    "www.codeberg.org",
    "sourceforge.net",
    "www.sourceforge.net",
    "gitbox.apache.org",
    "git-wip-us.apache.org",
    "salsa.debian.org",
    "invent.kde.org",
}

ARTIFACT_HOST_PATTERNS = {
    "registry.npmjs.org",
    "www.npmjs.com",
    "npmjs.com",
    "files.pythonhosted.org",
    "pypi.org",
    "www.pypi.org",
    "repo1.maven.org",
    "repo.maven.apache.org",
    "search.maven.org",
}

COMMON_SPDX_IDS = {
    "0BSD",
    "AFL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-1.1",
    "Apache-2.0",
    "Artistic-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-4-Clause",
    "BSL-1.0",
    "CC-BY-3.0",
    "CC-BY-4.0",
    "CC-BY-SA-3.0",
    "CC-BY-SA-4.0",
    "CC0-1.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "EPL-1.0",
    "EPL-2.0",
    "GPL-1.0-only",
    "GPL-1.0-or-later",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MPL-1.1",
    "MPL-2.0",
    "MS-PL",
    "OFL-1.1",
    "OSL-3.0",
    "PostgreSQL",
    "Python-2.0",
    "Unlicense",
    "WTFPL",
    "Zlib",
}


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

    return value == "" or value.lower() in MISSING_VALUES


def truthy(value):
    return lower(value) in {
        "true",
        "1",
        "yes",
        "y",
    }


def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(f"Missing input file: {path}")

    with path.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def write_csv(path, rows, fieldnames=None):
    path.parent.mkdir(parents=True, exist_ok=True)

    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []

    with path.open("w", newline="", encoding="utf-8") as file:
        if not fieldnames:
            return

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(rows)


def make_key(row):
    """
    Construct a component-level key for joining provenance and evidence.

    component_id is used when available. The remaining fields provide
    additional protection against accidental cross-component matches.
    """

    return (
        clean(row.get("component_id")),
        clean(row.get("project_id")),
        clean(row.get("tool")),
        clean(row.get("sbom_path")),
        clean(row.get("component_index")),
    )


def make_fallback_key(row):
    """
    Fallback key for files where component_id may be absent.
    """

    return (
        clean(row.get("project_id")),
        clean(row.get("tool")),
        clean(row.get("sbom_path")),
        clean(row.get("component_index")),
    )


def build_evidence_indexes(rows):
    primary_index = {}
    fallback_index = {}

    for row in rows:
        primary_key = make_key(row)
        fallback_key = make_fallback_key(row)

        primary_index[primary_key] = row

        if fallback_key not in fallback_index:
            fallback_index[fallback_key] = row

    return primary_index, fallback_index


def find_evidence(
    proposal,
    primary_index,
    fallback_index,
):
    evidence = primary_index.get(make_key(proposal))

    if evidence is not None:
        return evidence

    return fallback_index.get(make_fallback_key(proposal))


def parse_http_url(value):
    """
    Parse only HTTP or HTTPS URLs.
    """

    value = clean(value)

    if not value:
        return None

    try:
        parsed = urllib.parse.urlparse(value)
    except Exception:
        return None

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return None

    if not parsed.netloc:
        return None

    return parsed


def strip_repository_fragment(value):
    """
    Remove common GitHub/GitLab browsing fragments from repository URLs.

    This does not attempt to remove meaningful repository subdirectory
    information. It only removes URL query strings and fragments.
    """

    parsed = parse_http_url(value)

    if parsed is None:
        return clean(value)

    normalized = parsed._replace(
        query="",
        fragment="",
    ).geturl()

    return normalized.rstrip("/")


def normalize_repository_url(value):
    """
    Convert common repository-reference formats into canonical HTTPS URLs.

    Supported forms include:

    - https://github.com/user/repository
    - http://github.com/user/repository
    - git://github.com/user/repository
    - git+https://github.com/user/repository.git
    - git+ssh://git@github.com/user/repository.git
    - ssh://git@github.com/user/repository
    - git@github.com:user/repository
    - github:user/repository

    Returns:
        normalized_url
        normalization_rule
    """

    original = clean(value)

    if not original:
        return "", "empty_repository_value"

    value = original.strip()

    # Remove common SCM prefixes.
    if value.lower().startswith("scm:"):
        value = value[4:]

    if value.lower().startswith("git+"):
        value = value[4:]

    # GitHub shorthand sometimes used by npm:
    # github:user/repository
    github_shorthand = re.fullmatch(
        r"github:([^/\s]+)/([^/\s]+)",
        value,
        re.IGNORECASE,
    )

    if github_shorthand:
        owner = github_shorthand.group(1)
        repository = github_shorthand.group(2)

        repository = re.sub(
            r"\.git$",
            "",
            repository,
            flags=re.IGNORECASE,
        )

        normalized = (
            f"https://github.com/{owner}/{repository}"
        )

        return (
            normalized.rstrip("/"),
            "normalized_github_shorthand",
        )

    # SCP-like SSH form:
    # git@github.com:owner/repository
    scp_match = re.fullmatch(
        r"(?P<user>[A-Za-z0-9._-]+)@"
        r"(?P<host>[^:\s]+):"
        r"(?P<path>.+)",
        value,
    )

    if scp_match:
        host = scp_match.group("host")
        path = scp_match.group("path").lstrip("/")

        path = re.sub(
            r"\.git$",
            "",
            path,
            flags=re.IGNORECASE,
        )

        normalized = f"https://{host}/{path}"

        return (
            normalized.rstrip("/"),
            "normalized_scp_like_git_url",
        )

    # git://host/path
    if value.lower().startswith("git://"):
        normalized = (
            "https://"
            + value[len("git://"):]
        )

        normalized = re.sub(
            r"\.git$",
            "",
            normalized,
            flags=re.IGNORECASE,
        )

        normalized = strip_repository_fragment(normalized)

        return (
            normalized.rstrip("/"),
            "normalized_git_protocol_url",
        )

    # ssh://git@host/path
    if value.lower().startswith("ssh://"):
        try:
            parsed = urllib.parse.urlparse(value)
        except Exception:
            return (
                original,
                "repository_url_not_normalized",
            )

        host = parsed.hostname
        path = parsed.path.lstrip("/")

        if host and path:
            path = re.sub(
                r"\.git$",
                "",
                path,
                flags=re.IGNORECASE,
            )

            normalized = f"https://{host}/{path}"

            return (
                normalized.rstrip("/"),
                "normalized_ssh_repository_url",
            )

    # Standard HTTP or HTTPS repository URL.
    if value.lower().startswith(
        (
            "http://",
            "https://",
        )
    ):
        parsed = parse_http_url(value)

        if parsed is None:
            return (
                original,
                "repository_url_not_normalized",
            )

        scheme = "https"

        normalized = parsed._replace(
            scheme=scheme,
            query="",
            fragment="",
        ).geturl()

        normalized = re.sub(
            r"\.git$",
            "",
            normalized,
            flags=re.IGNORECASE,
        )

        return (
            normalized.rstrip("/"),
            "repository_url_already_http",
        )

    return (
        original,
        "repository_url_not_normalized",
    )


def extract_purl_coordinates(purl):
    result = {
        "type": "",
        "namespace": "",
        "name": "",
        "version": "",
    }

    purl = clean(purl)

    if not purl.startswith("pkg:") or "/" not in purl:
        return result

    without_prefix = purl[4:]

    try:
        purl_type, rest = without_prefix.split("/", 1)
    except ValueError:
        return result

    result["type"] = purl_type.lower()

    if "?" in rest:
        rest = rest.split("?", 1)[0]

    if "#" in rest:
        rest = rest.split("#", 1)[0]

    if "@" in rest:
        path_part, version = rest.rsplit("@", 1)
        result["version"] = urllib.parse.unquote(version)
    else:
        path_part = rest

    path_part = urllib.parse.unquote(path_part)

    if result["type"] == "maven":
        parts = path_part.split("/")

        if len(parts) >= 2:
            result["namespace"] = "/".join(parts[:-1])
            result["name"] = parts[-1]
        else:
            result["name"] = path_part
    else:
        result["name"] = path_part

    return result


def base_checks(proposal, evidence):
    rules = []
    problems = []

    old_value = clean(proposal.get("old_value"))
    new_value = clean(proposal.get("new_value"))

    if not is_missing(old_value):
        problems.append("old_value_not_missing")
    else:
        rules.append("old_value_was_missing")

    if is_missing(new_value):
        problems.append("new_value_missing")
    else:
        rules.append("new_value_present")

    if evidence is None:
        problems.append("evidence_record_missing")
        return rules, problems

    evidence_status = lower(
        evidence.get("evidence_status")
    )

    if evidence_status != "success":
        problems.append(
            "evidence_retrieval_not_successful"
        )
    else:
        rules.append(
            "evidence_retrieval_successful"
        )

    exact_match = evidence.get(
        "evidence_exact_version_match"
    )

    if not truthy(exact_match):
        problems.append(
            "exact_version_not_confirmed"
        )
    else:
        rules.append("exact_version_confirmed")

    confidence = lower(
        evidence.get("evidence_confidence")
    )

    if confidence not in {
        "high",
        "medium",
    }:
        problems.append(
            "evidence_confidence_not_acceptable"
        )
    else:
        rules.append(
            f"evidence_confidence_{confidence}"
        )

    return rules, problems


def validate_license(proposal, evidence):
    value = clean(proposal.get("new_value"))

    if is_missing(value):
        return (
            "fail",
            "high",
            ["license_missing"],
            "The proposed license value is empty.",
        )

    if value.startswith(
        (
            "http://",
            "https://",
        )
    ):
        return (
            "out_of_scope",
            "medium",
            ["license_url_only"],
            (
                "The value is a license URL. Static validation "
                "cannot establish its exact SPDX equivalent."
            ),
        )

    if value in COMMON_SPDX_IDS:
        return (
            "pass",
            "high",
            ["recognized_common_spdx_id"],
            (
                "The proposed value is a recognized common "
                "SPDX identifier."
            ),
        )

    # LicenseRef values are permitted in SPDX, but their meaning
    # is document-specific and therefore not semantically verified.
    if re.fullmatch(
        r"(DocumentRef-[A-Za-z0-9.\-]+:)?"
        r"LicenseRef-[A-Za-z0-9.\-]+",
        value,
    ):
        return (
            "out_of_scope",
            "medium",
            ["spdx_license_reference"],
            (
                "The value uses SPDX LicenseRef syntax, but "
                "static validation cannot determine its meaning."
            ),
        )

    spdx_token = (
        r"(?:[A-Za-z0-9.\-+]+|"
        r"(?:DocumentRef-[A-Za-z0-9.\-]+:)?"
        r"LicenseRef-[A-Za-z0-9.\-]+)"
    )

    spdx_expression_pattern = re.compile(
        rf"^\(?{spdx_token}\)?"
        rf"(?:\s+(?:AND|OR|WITH)\s+"
        rf"\(?{spdx_token}\)?)+$",
        re.IGNORECASE,
    )

    if spdx_expression_pattern.fullmatch(value):
        return (
            "pass",
            "medium",
            ["spdx_expression_like_syntax"],
            (
                "The value has SPDX-expression-like syntax. "
                "Static validation does not independently confirm "
                "every identifier in the expression."
            ),
        )

    classifier_markers = [
        "license ::",
        "osi approved",
        "free software license",
    ]

    if any(
        marker in value.lower()
        for marker in classifier_markers
    ):
        return (
            "out_of_scope",
            "medium",
            ["registry_classifier_text"],
            (
                "The value is registry classifier text and "
                "requires semantic normalization to SPDX."
            ),
        )

    if len(value) > 150:
        return (
            "out_of_scope",
            "low",
            ["long_free_text_license"],
            (
                "The proposed value appears to be free-text "
                "license metadata."
            ),
        )

    if re.fullmatch(
        r"[A-Za-z0-9.\-+(),/ ]+",
        value,
    ):
        return (
            "out_of_scope",
            "medium",
            ["unverified_license_name"],
            (
                "The value resembles a license name, but static "
                "checks cannot confirm its SPDX equivalence."
            ),
        )

    return (
        "out_of_scope",
        "low",
        ["unrecognized_license_format"],
        (
            "The proposed license format cannot be conclusively "
            "validated using deterministic rules."
        ),
    )


def validate_repository_url(proposal, evidence):
    original_value = clean(
        proposal.get("new_value")
    )

    (
        normalized_value,
        normalization_rule,
    ) = normalize_repository_url(original_value)

    parsed = parse_http_url(normalized_value)

    if parsed is None:
        return (
            "fail",
            "high",
            [
                "repository_url_invalid",
                normalization_rule,
            ],
            (
                "The proposed repository value could not be "
                "interpreted as an HTTP, HTTPS, Git, SSH, "
                "SCP-style, or supported shorthand repository URL."
            ),
        )

    host = (
        parsed.hostname.lower()
        if parsed.hostname
        else ""
    )

    path = urllib.parse.unquote(
        parsed.path
    ).lower()

    distribution = ""

    if evidence:
        distribution = clean(
            evidence.get(
                "evidence_distribution_url"
            )
        )

    normalized_distribution = ""

    if distribution:
        (
            normalized_distribution,
            _,
        ) = normalize_repository_url(distribution)

    if (
        normalized_distribution
        and normalized_value.rstrip("/")
        == normalized_distribution.rstrip("/")
    ):
        return (
            "fail",
            "high",
            [
                "repository_equals_distribution_url",
                normalization_rule,
            ],
            (
                "The repository URL is identical to the package "
                "distribution URL."
            ),
        )

    if host in ARTIFACT_HOST_PATTERNS:
        return (
            "fail",
            "high",
            [
                "artifact_host_used_as_repository",
                normalization_rule,
            ],
            (
                "The URL points to a package registry or artifact "
                "host rather than a source-code repository."
            ),
        )

    artifact_suffixes = (
        ".tgz",
        ".tar.gz",
        ".tar.bz2",
        ".whl",
        ".zip",
        ".jar",
        ".pom",
        ".war",
        ".aar",
        ".deb",
        ".rpm",
    )

    if path.endswith(artifact_suffixes):
        return (
            "fail",
            "high",
            [
                "artifact_file_used_as_repository",
                normalization_rule,
            ],
            (
                "The URL points to a downloadable artifact rather "
                "than a source-code repository."
            ),
        )

    if host in KNOWN_VCS_HOSTS:
        path_parts = [
            part
            for part in parsed.path.split("/")
            if part
        ]

        if len(path_parts) < 2:
            return (
                "out_of_scope",
                "medium",
                [
                    "vcs_host_without_project_path",
                    normalization_rule,
                ],
                (
                    "The host is a known source-control service, "
                    "but the URL does not clearly identify a "
                    "repository."
                ),
            )

        if host in {
            "github.com",
            "www.github.com",
            "gitlab.com",
            "www.gitlab.com",
            "bitbucket.org",
            "www.bitbucket.org",
            "codeberg.org",
            "www.codeberg.org",
        }:
            repository_parts = path_parts[:2]

            if any(
                part.lower()
                in {
                    "issues",
                    "pull",
                    "pulls",
                    "releases",
                    "wiki",
                }
                for part in repository_parts
            ):
                return (
                    "out_of_scope",
                    "medium",
                    [
                        "unexpected_vcs_path",
                        normalization_rule,
                    ],
                    (
                        "The host is a source-control service, "
                        "but the path does not clearly identify "
                        "a repository root."
                    ),
                )

        return (
            "pass",
            "medium",
            [
                "valid_repository_reference",
                "known_vcs_host",
                "repository_path_present",
                normalization_rule,
            ],
            (
                "The proposed value identifies a repository on "
                "a known source-control host. A non-HTTP Git or "
                "SSH reference was normalized where necessary. "
                "Static validation does not independently prove "
                "package ownership."
            ),
        )

    return (
        "out_of_scope",
        "medium",
        [
            "valid_repository_reference",
            "unknown_or_general_host",
            normalization_rule,
        ],
        (
            "The repository reference is structurally valid, "
            "but static checks cannot determine whether the host "
            "represents a source repository or project homepage."
        ),
    )


def validate_supplier(proposal, evidence):
    """Static checks for supplier proposals.

    Party-role semantics are deliberately *not* resolved here.  The goal of
    this stage is to verify that the value is structurally usable and to
    preserve the exact role exposed by the registry.  Author, maintainer,
    developer, organization, publisher/account and scope metadata are not
    automatically equivalent to a CycloneDX supplier.
    """
    value = clean(proposal.get("new_value"))

    if is_missing(value):
        return (
            "fail",
            "high",
            ["supplier_missing"],
            "The proposed supplier value is empty.",
        )

    if value.lower() in MISSING_VALUES:
        return (
            "fail",
            "high",
            ["supplier_placeholder"],
            "The proposed supplier is a placeholder value.",
        )

    if len(value) > 300:
        return (
            "fail",
            "medium",
            ["supplier_value_excessively_long"],
            "The supplier value is unexpectedly long.",
        )

    role = lower(
        proposal.get("evidence_party_role")
        or (evidence.get("evidence_party_role") if evidence else "")
        or (evidence.get("evidence_supplier_role") if evidence else "")
    )
    source_field = clean(
        proposal.get("evidence_party_source_field")
        or (evidence.get("evidence_party_source_field") if evidence else "")
    )

    ecosystem = (
        lower(proposal.get("ecosystem"))
        or lower(proposal.get("component_ecosystem"))
    )
    if not ecosystem:
        coords = extract_purl_coordinates(proposal.get("purl"))
        ecosystem = coords["type"]

    # A role that explicitly denotes a supplier-like relationship may pass
    # this structural layer, but it still proceeds to semantic validation.
    explicit_supplier_roles = {
        "supplier",
        "vendor",
        "manufacturer",
        "producer",
        "distributor",
    }
    if role in explicit_supplier_roles:
        return (
            "pass",
            "high",
            [f"party_role_{role}", "explicit_supplier_role_recorded"],
            (
                f"The retrieved party is explicitly labelled with the role '{role}'. "
                "Static validation confirms the role is recorded but does not by itself "
                "establish final CycloneDX field correctness."
            ),
        )

    # These registry roles are useful party metadata, but their meaning is
    # not automatically equivalent to supplier.  Publisher is intentionally
    # included here rather than treated as an explicit supplier.
    ambiguous_roles = {
        "author",
        "maintainer",
        "developer",
        "organization",
        "developer_organization",
        "owner",
        "npm_scope",
        "scope",
        "namespace",
        "publisher",
        "publisher_account",
        "author_email",
        "maintainer_email",
        "contact",
        "email",
    }

    if role in ambiguous_roles:
        rules = [f"party_role_{role}", "supplier_role_not_equivalent"]

        # Keep legacy category labels where useful for summaries/routing.
        if role == "npm_scope":
            rules.append("npm_scope_as_supplier")
        elif role in {"author", "maintainer"} and ecosystem == "pypi":
            rules.append("pypi_author_or_maintainer")
        elif role in {"developer", "organization", "developer_organization"} and ecosystem == "maven":
            rules.append("maven_organization_or_developer")
        elif role in {"author_email", "maintainer_email", "email"}:
            rules.append("email_like_supplier")

        details = f" Source field: {source_field}." if source_field else ""
        return (
            "out_of_scope",
            "high",
            rules,
            (
                f"The retrieved party is recorded as '{role}', which is not automatically "
                "equivalent to a CycloneDX supplier. Supplier suitability therefore "
                "requires semantic validation." + details
            ),
        )

    if "@" in value and " " not in value and not value.startswith("@"):
        return (
            "out_of_scope",
            "medium",
            ["email_like_supplier", "supplier_role_unavailable"],
            (
                "The value resembles an email address, but no explicit supplier role "
                "is available. Semantic validation is required."
            ),
        )

    return (
        "out_of_scope",
        "medium",
        ["supplier_semantics_unverified", "supplier_role_unavailable"],
        (
            "The party value is structurally plausible, but its registry role does not "
            "establish that it is the CycloneDX supplier."
        ),
    )


def npm_distribution_matches(value, coords):
    parsed = parse_http_url(value)

    if parsed is None:
        return (
            False,
            ["invalid_distribution_url"],
        )

    host = (
        parsed.hostname.lower()
        if parsed.hostname
        else ""
    )

    path = urllib.parse.unquote(
        parsed.path
    ).lower()

    package_name = coords["name"].lower()
    version = coords["version"].lower()

    if host != "registry.npmjs.org":
        return (
            False,
            ["unexpected_npm_distribution_host"],
        )

    name_tail = package_name.split("/")[-1]

    if version and version not in path:
        return (
            False,
            ["npm_version_not_in_distribution_url"],
        )

    if name_tail and name_tail not in path:
        return (
            False,
            ["npm_package_name_not_in_distribution_url"],
        )

    if not path.endswith(".tgz"):
        return (
            False,
            ["npm_distribution_not_tgz"],
        )

    return (
        True,
        [
            "npm_registry_host_match",
            "npm_package_name_match",
            "npm_version_match",
            "npm_tarball_suffix",
        ],
    )


def pypi_distribution_matches(value, coords):
    parsed = parse_http_url(value)

    if parsed is None:
        return (
            False,
            ["invalid_distribution_url"],
        )

    host = (
        parsed.hostname.lower()
        if parsed.hostname
        else ""
    )

    path = urllib.parse.unquote(
        parsed.path
    ).lower()

    if host not in {
        "files.pythonhosted.org",
        "pypi.org",
        "www.pypi.org",
    }:
        return (
            False,
            ["unexpected_pypi_distribution_host"],
        )

    version = coords["version"].lower()
    package_name = coords["name"].lower()

    normalized_package_name = re.sub(
        r"[-_.]+",
        "-",
        package_name,
    )

    normalized_path = re.sub(
        r"[-_.]+",
        "-",
        path,
    )

    if version and version not in path:
        return (
            False,
            ["pypi_version_not_in_distribution_url"],
        )

    if (
        normalized_package_name
        and normalized_package_name
        not in normalized_path
    ):
        return (
            False,
            ["pypi_package_name_not_in_distribution_url"],
        )

    valid_suffixes = (
        ".whl",
        ".tar.gz",
        ".zip",
        ".tar.bz2",
    )

    if not path.endswith(valid_suffixes):
        return (
            False,
            ["unexpected_pypi_artifact_suffix"],
        )

    return (
        True,
        [
            "pypi_artifact_host_match",
            "pypi_package_name_match",
            "pypi_version_match",
            "pypi_artifact_suffix_valid",
        ],
    )


def maven_distribution_matches(value, coords):
    parsed = parse_http_url(value)

    if parsed is None:
        return (
            False,
            ["invalid_distribution_url"],
        )

    host = (
        parsed.hostname.lower()
        if parsed.hostname
        else ""
    )

    path = urllib.parse.unquote(
        parsed.path
    ).lower()

    if host not in {
        "repo1.maven.org",
        "repo.maven.apache.org",
    }:
        return (
            False,
            ["unexpected_maven_distribution_host"],
        )

    artifact = coords["name"].lower()
    version = coords["version"].lower()

    namespace_path = (
        coords["namespace"]
        .replace(".", "/")
        .lower()
    )

    if artifact and artifact not in path:
        return (
            False,
            ["maven_artifact_not_in_distribution_url"],
        )

    if version and version not in path:
        return (
            False,
            ["maven_version_not_in_distribution_url"],
        )

    if namespace_path and namespace_path not in path:
        return (
            False,
            ["maven_namespace_not_in_distribution_url"],
        )

    if not path.endswith(
        (
            ".jar",
            ".pom",
            ".war",
            ".aar",
            ".zip",
        )
    ):
        return (
            False,
            ["unexpected_maven_artifact_suffix"],
        )

    return (
        True,
        [
            "maven_repository_host_match",
            "maven_namespace_match",
            "maven_artifact_match",
            "maven_version_match",
            "maven_artifact_suffix_valid",
        ],
    )


def split_distribution_urls(value):
    """Split a field containing one or more distribution URLs.

    Retrieval may preserve several exact-version artifacts (especially for
    PyPI).  Semicolons used inside an ordinary URL are not treated as
    separators unless the following token starts another HTTP(S) URL.
    Newlines are also accepted as separators.
    """
    text = clean(value)
    if not text:
        return []

    parts = re.split(
        r"(?:\r?\n)+|\s*;\s*(?=https?://)",
        text,
        flags=re.IGNORECASE,
    )
    return [part.strip() for part in parts if part.strip()]


def canonical_artifact_url(value):
    """Canonicalize an HTTP(S) artifact URL for strict identity checking."""
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


def validate_distribution_url(proposal, evidence):
    value = clean(proposal.get("new_value"))
    urls = split_distribution_urls(value)

    if not urls:
        return (
            "fail",
            "high",
            ["distribution_url_missing"],
            "No usable distribution URL was found in the proposed value.",
        )

    coords = extract_purl_coordinates(proposal.get("purl"))

    if not coords["type"]:
        return (
            "out_of_scope",
            "low",
            ["purl_type_missing"],
            "The component ecosystem cannot be inferred from its purl.",
        )

    if not coords["version"]:
        return (
            "out_of_scope",
            "low",
            ["purl_version_missing"],
            "The exact component version is unavailable for URL validation.",
        )

    matcher = {
        "npm": npm_distribution_matches,
        "pypi": pypi_distribution_matches,
        "maven": maven_distribution_matches,
    }.get(coords["type"])

    if matcher is None:
        return (
            "out_of_scope",
            "low",
            ["unsupported_distribution_ecosystem"],
            "Static distribution URL validation is not implemented for this ecosystem.",
        )

    all_rules = []
    failed_urls = []

    for url in urls:
        matched, rules = matcher(url, coords)
        all_rules.extend(rules)
        if not matched:
            failed_urls.append(url)

    all_rules = sorted(set(all_rules))
    all_rules.append(f"distribution_url_count:{len(urls)}")

    if failed_urls:
        all_rules.append(f"invalid_distribution_url_count:{len(failed_urls)}")
        return (
            "fail",
            "high",
            all_rules,
            (
                f"{len(failed_urls)} of {len(urls)} proposed distribution URL(s) are "
                "inconsistent with the component ecosystem, package identity, version, "
                "or expected artifact format."
            ),
        )

    if len(urls) > 1:
        all_rules.append("multiple_distribution_urls_valid")

    return (
        "pass",
        "high",
        all_rules,
        (
            f"All {len(urls)} proposed distribution URL(s) are structurally consistent "
            "with the exact package ecosystem, identity, version, and artifact format."
        ),
    )


def is_hex(value, expected_length):
    return (
        len(value) == expected_length
        and re.fullmatch(
            r"[0-9a-fA-F]+",
            value,
        )
        is not None
    )


def looks_like_integrity(value):
    match = re.fullmatch(
        r"(sha256|sha384|sha512)-"
        r"([A-Za-z0-9+/=]+)",
        value,
        re.IGNORECASE,
    )

    if not match:
        return False

    try:
        base64.b64decode(
            match.group(2),
            validate=True,
        )
    except Exception:
        return False

    return True


def parse_hash_values(value):
    """
    Parse hash values separated by semicolons or vertical bars.

    Commas are not used as separators because some source formats
    may embed them in serialized values.
    """

    return [
        part.strip()
        for part in re.split(r"[;|]", clean(value))
        if part.strip()
    ]


def validate_hash_values(proposal, evidence):
    """Validate hash proposals only after exact-artifact identity is established."""
    value = clean(proposal.get("new_value"))

    if is_missing(value):
        return (
            "fail",
            "high",
            ["hash_missing"],
            "The proposed hash value is empty.",
        )

    if evidence is None:
        return (
            "fail",
            "high",
            ["hash_evidence_record_missing"],
            "No retrieval record is available to establish artifact-specific hash identity.",
        )

    usable = truthy(evidence.get("evidence_hash_usable_for_auto_repair"))
    artifact_match = truthy(evidence.get("evidence_artifact_match"))
    match_method = lower(evidence.get("evidence_artifact_match_method"))
    hash_status = lower(evidence.get("evidence_hash_status"))
    input_artifact = clean(evidence.get("evidence_input_artifact_url"))
    matched_artifact = clean(evidence.get("evidence_artifact_url"))

    artifact_rules = []

    # A hash may be automatically proposed only for one uniquely identified
    # input artifact.  This catches cases where a field contains both an sdist
    # and one or more wheels even if package/version identity is exact.
    input_artifacts = split_distribution_urls(input_artifact)
    if len(input_artifacts) > 1:
        return (
            "fail",
            "high",
            ["multiple_input_artifacts_for_hash"],
            (
                "The original component metadata identifies multiple distribution "
                "artifacts, so a single artifact-specific hash cannot be assigned safely."
            ),
        )

    if not usable:
        return (
            "fail",
            "high",
            ["hash_not_usable_for_auto_repair"],
            (
                "The retrieval stage did not mark this hash as usable for automatic "
                "repair of the exact artifact."
            ),
        )

    artifact_rules.append("hash_usable_for_auto_repair")

    if not artifact_match:
        return (
            "fail",
            "high",
            ["exact_artifact_not_matched"],
            "The retrieved hash is not tied to an exactly matched artifact.",
        )

    artifact_rules.append("exact_artifact_match_confirmed")

    if match_method:
        artifact_rules.append(f"artifact_match_method:{match_method}")

    if hash_status:
        artifact_rules.append(f"hash_status:{hash_status}")
        if hash_status != "exact_artifact_hash_available":
            return (
                "fail",
                "high",
                artifact_rules + ["hash_status_not_exact_artifact_available"],
                (
                    "The retrieval status does not confirm that an exact-artifact hash "
                    "is available for automatic repair."
                ),
            )

    if input_artifacts and matched_artifact:
        left = canonical_artifact_url(input_artifacts[0])
        right = canonical_artifact_url(matched_artifact)
        if not left or not right or left != right:
            return (
                "fail",
                "high",
                artifact_rules + ["artifact_url_recheck_failed"],
                (
                    "The static recheck could not confirm that the input artifact URL "
                    "and the registry artifact URL identify the same exact artifact."
                ),
            )
        artifact_rules.append("artifact_url_recheck_passed")

    algorithm_text = clean(evidence.get("evidence_hash_algorithms"))
    algorithms = [
        part.strip().lower()
        for part in re.split(r"[;|,]", algorithm_text)
        if part.strip()
    ]

    values = parse_hash_values(value)

    if not values:
        return (
            "fail",
            "high",
            artifact_rules + ["hash_values_empty"],
            "No usable hash values were found.",
        )

    plausible_values = all(
        is_hex(hash_value, 32)
        or is_hex(hash_value, 40)
        or is_hex(hash_value, 64)
        or is_hex(hash_value, 96)
        or is_hex(hash_value, 128)
        or looks_like_integrity(hash_value)
        for hash_value in values
    )

    if not algorithms:
        if plausible_values:
            return (
                "out_of_scope",
                "medium",
                artifact_rules + ["hash_format_valid_algorithm_unknown"],
                (
                    "The hash is tied to the exact artifact and has a plausible format, "
                    "but its algorithm cannot be conclusively linked to the value."
                ),
            )

        return (
            "fail",
            "high",
            artifact_rules + ["hash_format_invalid"],
            "The proposed hash values do not match known digest formats.",
        )

    if len(algorithms) != len(values):
        return (
            "out_of_scope",
            "medium",
            artifact_rules + ["hash_algorithm_value_count_mismatch"],
            (
                "The number of stated hash algorithms differs from the number of "
                "proposed hash values."
            ),
        )

    failures = []
    passes = []

    expected_lengths = {
        "md5": 32,
        "sha1": 40,
        "sha-1": 40,
        "sha256": 64,
        "sha-256": 64,
        "sha384": 96,
        "sha-384": 96,
        "sha512": 128,
        "sha-512": 128,
        # PyPI exposes BLAKE2b-256 digests under the blake2b_256 key.
        # A BLAKE2b-256 digest is 256 bits = 64 hexadecimal characters.
        "blake2b_256": 64,
        "blake2b-256": 64,
    }

    for algorithm, hash_value in zip(algorithms, values):
        if algorithm in {"integrity", "sri"}:
            if looks_like_integrity(hash_value):
                passes.append("integrity_format_valid")
            else:
                failures.append("integrity_format_invalid")
            continue

        expected_length = expected_lengths.get(algorithm)
        if expected_length is None:
            failures.append(f"unsupported_hash_algorithm:{algorithm}")
            continue

        if is_hex(hash_value, expected_length):
            passes.append(f"{algorithm}_format_valid")
        else:
            failures.append(f"{algorithm}_format_invalid")

    if failures:
        unsupported_only = all(
            item.startswith("unsupported_hash_algorithm") for item in failures
        )
        if unsupported_only:
            return (
                "out_of_scope",
                "medium",
                artifact_rules + passes + failures,
                "The hash algorithm is not covered by the current static validation rules.",
            )

        return (
            "fail",
            "high",
            artifact_rules + passes + failures,
            "At least one proposed hash does not match the format required by its stated algorithm.",
        )

    return (
        "pass",
        "high",
        artifact_rules + passes,
        (
            "The hash is tied to an exactly matched artifact and all proposed hash "
            "values match their stated digest algorithms."
        ),
    )


def validate_field(proposal, evidence):
    field = clean(
        proposal.get("field_name")
    )

    if field == "license":
        return validate_license(
            proposal,
            evidence,
        )

    if field == "repository_url":
        return validate_repository_url(
            proposal,
            evidence,
        )

    if field == "supplier":
        return validate_supplier(
            proposal,
            evidence,
        )

    if field == "distribution_url":
        return validate_distribution_url(
            proposal,
            evidence,
        )

    if field == "hash_values":
        return validate_hash_values(
            proposal,
            evidence,
        )

    return (
        "out_of_scope",
        "low",
        ["unsupported_field"],
        (
            "No static validation rule is implemented for "
            f"field: {field}"
        ),
    )


def combine_result(
    base_problems,
    field_result,
):
    severe_problems = {
        "old_value_not_missing",
        "new_value_missing",
        "evidence_record_missing",
        "evidence_retrieval_not_successful",
        "exact_version_not_confirmed",
        "evidence_confidence_not_acceptable",
    }

    if any(
        problem in severe_problems
        for problem in base_problems
    ):
        return "fail"

    return field_result


def review_priority(
    result,
    confidence,
    field,
):
    if result == "fail":
        return "high"

    if result == "out_of_scope":
        if field in {
            "supplier",
            "repository_url",
        }:
            return "high"

        if confidence == "low":
            return "high"

        return "medium"

    return "low"


def llm_review_suitability(
    result,
    field,
    rules,
):
    """
    Identify whether a proposal is suitable for LLM-assisted review.

    Hash verification and clear deterministic failures should normally
    be handled programmatically or manually rather than delegated to
    an LLM.
    """

    rule_set = set(rules)

    if result == "pass":
        return (
            "sample_only",
            "Static pass; include only in a validation sample.",
        )

    if field == "supplier":
        return (
            "yes",
            (
                "Supplier semantics require interpretation of "
                "organization, author, maintainer, or scope evidence."
            ),
        )

    if field == "license":
        return (
            "yes",
            (
                "Free-text or classifier-style license metadata "
                "may benefit from constrained semantic normalization."
            ),
        )

    if field == "repository_url":
        if {
            "artifact_host_used_as_repository",
            "artifact_file_used_as_repository",
            "repository_equals_distribution_url",
        } & rule_set:
            return (
                "no",
                (
                    "The failure is deterministic and does not "
                    "require LLM interpretation."
                ),
            )

        return (
            "yes",
            (
                "Repository ownership or homepage-versus-source "
                "semantics may require interpretation."
            ),
        )

    if field == "hash_values":
        return (
            "no",
            (
                "Hash correctness should be established using "
                "artifact evidence or deterministic checks, not an LLM."
            ),
        )

    if field == "distribution_url":
        return (
            "no",
            (
                "Distribution URL consistency is best handled by "
                "deterministic package and version checks."
            ),
        )

    return (
        "no",
        (
            "The case is not assigned to LLM-assisted validation."
        ),
    )


def create_summaries(rows):
    total = len(rows)

    overall_counts = Counter(
        row["static_validation_result"]
        for row in rows
    )

    summary_rows = []

    preferred_order = [
        "pass",
        "out_of_scope",
        "fail",
    ]

    for result in preferred_order:
        count = overall_counts.get(result, 0)

        summary_rows.append(
            {
                "static_validation_result": result,
                "count": count,
                "percentage": (
                    f"{count / total * 100:.2f}"
                    if total
                    else "0.00"
                ),
            }
        )

    write_csv(
        OUTPUT_SUMMARY,
        summary_rows,
        [
            "static_validation_result",
            "count",
            "percentage",
        ],
    )

    by_field = Counter(
        (
            row["field_name"],
            row["static_validation_result"],
        )
        for row in rows
    )

    field_totals = Counter(
        row["field_name"]
        for row in rows
    )

    field_rows = []

    for field in sorted(field_totals):
        for result in preferred_order:
            count = by_field.get(
                (
                    field,
                    result,
                ),
                0,
            )

            if count == 0:
                continue

            field_rows.append(
                {
                    "field_name": field,
                    "static_validation_result": result,
                    "count": count,
                    "percentage_within_field": (
                        f"{count / field_totals[field] * 100:.2f}"
                        if field_totals[field]
                        else "0.00"
                    ),
                }
            )

    write_csv(
        OUTPUT_BY_FIELD,
        field_rows,
        [
            "field_name",
            "static_validation_result",
            "count",
            "percentage_within_field",
        ],
    )

    by_ecosystem = Counter(
        (
            row.get("ecosystem", ""),
            row["field_name"],
            row["static_validation_result"],
        )
        for row in rows
    )

    ecosystem_field_totals = Counter(
        (
            row.get("ecosystem", ""),
            row["field_name"],
        )
        for row in rows
    )

    ecosystem_rows = []

    ecosystem_field_pairs = sorted(
        ecosystem_field_totals
    )

    for ecosystem, field in ecosystem_field_pairs:
        for result in preferred_order:
            count = by_ecosystem.get(
                (
                    ecosystem,
                    field,
                    result,
                ),
                0,
            )

            if count == 0:
                continue

            total_for_group = (
                ecosystem_field_totals[
                    (
                        ecosystem,
                        field,
                    )
                ]
            )

            ecosystem_rows.append(
                {
                    "ecosystem": ecosystem,
                    "field_name": field,
                    "static_validation_result": result,
                    "count": count,
                    "percentage_within_ecosystem_field": (
                        f"{count / total_for_group * 100:.2f}"
                        if total_for_group
                        else "0.00"
                    ),
                }
            )

    write_csv(
        OUTPUT_BY_ECOSYSTEM,
        ecosystem_rows,
        [
            "ecosystem",
            "field_name",
            "static_validation_result",
            "count",
            "percentage_within_ecosystem_field",
        ],
    )


def main():
    proposals = load_csv(PROVENANCE_FILE)
    evidence_rows = load_csv(EVIDENCE_FILE)

    (
        evidence_primary_index,
        evidence_fallback_index,
    ) = build_evidence_indexes(evidence_rows)

    print(
        f"Loaded repair proposals: {len(proposals)}"
    )

    print(
        f"Loaded evidence rows: {len(evidence_rows)}"
    )

    validated_at = now_utc()

    output_rows = []
    review_rows = []

    evidence_matches = 0
    evidence_misses = 0

    for proposal in proposals:
        evidence = find_evidence(
            proposal,
            evidence_primary_index,
            evidence_fallback_index,
        )

        if evidence is None:
            evidence_misses += 1
        else:
            evidence_matches += 1

        (
            base_rules,
            base_problems,
        ) = base_checks(
            proposal,
            evidence,
        )

        (
            field_result,
            field_confidence,
            field_rules,
            field_reason,
        ) = validate_field(
            proposal,
            evidence,
        )

        final_result = combine_result(
            base_problems,
            field_result,
        )

        combined_rules = sorted(
            set(
                base_rules
                + field_rules
            )
        )

        combined_problems = sorted(
            set(base_problems)
        )

        if (
            final_result == "fail"
            and base_problems
        ):
            final_reason = (
                "Base evidence validation failed: "
                + "; ".join(base_problems)
                + ". "
                + field_reason
            )

            final_confidence = "high"
        else:
            final_reason = field_reason
            final_confidence = field_confidence

        field_name = clean(
            proposal.get("field_name")
        )

        (
            llm_suitability,
            llm_suitability_reason,
        ) = llm_review_suitability(
            final_result,
            field_name,
            combined_rules,
        )

        output = dict(proposal)

        # Carry the exact occurrence-level retrieval context forward.
        # This avoids a later component-only join and makes the static output
        # directly usable as input to semantic validation.
        output["evidence_join_status"] = "matched" if evidence is not None else "unmatched"
        for column in EVIDENCE_CONTEXT_COLUMNS:
            if evidence is not None:
                output[column] = clean(evidence.get(column))
            elif column not in output:
                output[column] = ""

        if field_name == "repository_url":
            (
                normalized_repository_url,
                repository_normalization_rule,
            ) = normalize_repository_url(
                proposal.get("new_value")
            )
        else:
            normalized_repository_url = ""
            repository_normalization_rule = ""

        output[
            "normalized_repository_url"
        ] = normalized_repository_url

        output[
            "repository_normalization_rule"
        ] = repository_normalization_rule

        output[
            "static_validation_result"
        ] = final_result

        output[
            "static_validation_confidence"
        ] = final_confidence

        output[
            "static_validation_rules"
        ] = ";".join(combined_rules)

        output[
            "static_validation_problems"
        ] = ";".join(combined_problems)

        output[
            "static_validation_reason"
        ] = final_reason

        output[
            "requires_llm_review"
        ] = (
            "yes"
            if llm_suitability == "yes"
            else "no"
        )

        output[
            "llm_review_suitability"
        ] = llm_suitability

        output[
            "llm_review_suitability_reason"
        ] = llm_suitability_reason

        output[
            "requires_human_review"
        ] = (
            "yes"
            if final_result
            in {
                "fail",
                "out_of_scope",
            }
            else "sample_only"
        )

        output[
            "review_priority"
        ] = review_priority(
            final_result,
            final_confidence,
            field_name,
        )

        output[
            "validated_at"
        ] = validated_at

        output_rows.append(output)

        if final_result in {
            "fail",
            "out_of_scope",
        }:
            review_rows.append(output)

    fieldnames = (
        list(output_rows[0].keys())
        if output_rows
        else []
    )

    write_csv(
        OUTPUT_ALL,
        output_rows,
        fieldnames,
    )

    write_csv(
        OUTPUT_REVIEW_QUEUE,
        review_rows,
        fieldnames,
    )

    create_summaries(output_rows)

    result_counts = Counter(
        row["static_validation_result"]
        for row in output_rows
    )

    print(
        f"\nEvidence matches: {evidence_matches}"
    )

    print(
        f"Evidence misses: {evidence_misses}"
    )

    print("\nStatic validation summary:")

    for result in [
        "pass",
        "out_of_scope",
        "fail",
    ]:
        count = result_counts.get(result, 0)

        percentage = (
            count / len(output_rows) * 100
            if output_rows
            else 0
        )

        print(
            f"{result}: "
            f"{count} "
            f"({percentage:.2f}%)"
        )

    print(
        "\nRepository URL normalization summary:"
    )

    normalization_counts = Counter(
        row["repository_normalization_rule"]
        for row in output_rows
        if row["field_name"]
        == "repository_url"
    )

    for rule, count in (
        normalization_counts.most_common()
    ):
        print(f"{rule}: {count}")

    supplier_roles = Counter(
        lower(row.get("evidence_party_role")) or "missing"
        for row in output_rows
        if row.get("field_name") == "supplier"
    )
    if supplier_roles:
        print("\nSupplier proposals by preserved party role:")
        for role, count in supplier_roles.most_common():
            print(f"{role}: {count}")

    hash_rows = [
        row for row in output_rows
        if row.get("field_name") == "hash_values"
    ]
    if hash_rows:
        print("\nHash proposal artifact checks:")
        for row in hash_rows:
            print(
                "component=" + clean(row.get("component_id"))
                + " result=" + clean(row.get("static_validation_result"))
                + " usable=" + clean(row.get("evidence_hash_usable_for_auto_repair"))
                + " artifact_match=" + clean(row.get("evidence_artifact_match"))
                + " method=" + clean(row.get("evidence_artifact_match_method"))
            )

    print(
        f"\nSaved all results to: {OUTPUT_ALL}"
    )

    print(
        "Saved review queue to: "
        f"{OUTPUT_REVIEW_QUEUE}"
    )

    print(
        f"Saved summary to: {OUTPUT_SUMMARY}"
    )

    print(
        "Saved field summary to: "
        f"{OUTPUT_BY_FIELD}"
    )

    print(
        "Saved ecosystem summary to: "
        f"{OUTPUT_BY_ECOSYSTEM}"
    )


if __name__ == "__main__":
    main()