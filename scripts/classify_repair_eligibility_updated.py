#!/usr/bin/env python3

import csv
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

INPUT_FILE = Path("data/component_metadata_raw.csv")

OUTPUT_FILE = Path("data/component_repair_candidates.csv")
SUMMARY_FILE = Path("data/component_repair_candidate_summary.csv")
SUMMARY_BY_ECOSYSTEM_TOOL_FILE = Path(
    "data/component_repair_candidate_summary_by_ecosystem_tool.csv"
)

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


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def lower(value):
    return clean(value).lower()


def is_missing(value):
    value = clean(value)
    if value == "":
        return True
    return value.lower() in MISSING_VALUES


def is_present(value):
    return not is_missing(value)


def get_component_id(row):
    purl = clean(row.get("purl"))
    if purl:
        return purl

    parts = [
        clean(row.get("project_id")),
        clean(row.get("tool")),
        clean(row.get("sbom_path")),
        clean(row.get("component_index")),
        clean(row.get("group")),
        clean(row.get("name")),
        clean(row.get("version")),
    ]
    return "|".join(parts)


def infer_ecosystem_from_purl(purl):
    purl = lower(purl)

    if purl.startswith("pkg:npm/"):
        return "npm"
    if purl.startswith("pkg:pypi/"):
        return "pypi"
    if purl.startswith("pkg:maven/"):
        return "maven"
    if purl.startswith("pkg:github/"):
        return "github"

    return ""


def normalize_ecosystem(row):
    """
    Return the component-level package ecosystem.

    IMPORTANT: a repository labelled as Maven/npm/PyPI can contain
    components from another ecosystem. Therefore the PURL type is the
    strongest component-level signal and takes precedence over the
    project-level `ecosystem` column.
    """
    purl = clean(row.get("purl"))

    inferred = infer_ecosystem_from_purl(purl)
    if inferred:
        return inferred

    ecosystem = lower(row.get("ecosystem"))
    if ecosystem:
        return ecosystem

    return ""


def project_ecosystem_label(row):
    """Preserve the original project-level ecosystem label for auditing."""
    return lower(row.get("ecosystem"))


def raw_text(row):
    fields = [
        "component_type",
        "bom_ref",
        "group",
        "name",
        "version",
        "purl",
        "scope",
        "repository_url",
        "website_url",
        "distribution_url",
        "issue_tracker_url",
        "external_references_raw",
        "component_raw_json",
        "sbom_path",
    ]
    return " ".join(lower(row.get(field)) for field in fields)


def has_github_action_evidence(row):
    text = raw_text(row)

    if "pkg:github/" in text:
        return True
    if "github-action" in text:
        return True
    if ".github/workflows" in text:
        return True
    if "github-actions" in text:
        return True
    if "actions/" in lower(row.get("name")):
        return True

    return False


def looks_local_fixture_or_test_artifact(row):
    text = raw_text(row)

    patterns = [
        "src/test",
        "src/inttest",
        "inttest",
        "integration-test",
        "integrationtest",
        "fixture",
        "fixtures",
        "sample",
        "samples",
        "example",
        "examples",
        "demo",
        "demos",
        "test-project",
        "test_project",
        "jar-deps",
        "dockerTest".lower(),
        "localnodemodulespath",
    ]

    if any(pattern in text for pattern in patterns):
        return True

    group = lower(row.get("group"))
    name = lower(row.get("name"))

    if group in {"com.example", "sample", "samples", "resources", "one", "two"}:
        return True

    if name in {"sample", "samples", "example", "demo", "one", "two", "resources"}:
        return True

    return False


def looks_internal_module(row):
    ecosystem = normalize_ecosystem(row)
    group = lower(row.get("group"))
    name = lower(row.get("name"))
    purl = lower(row.get("purl"))
    text = raw_text(row)

    internal_patterns = [
        "org.springframework.boot",
        "spring-boot",
        "build-plugin",
        "internal",
    ]

    if ecosystem == "maven":
        if group.startswith("org.springframework.boot") and "spring-boot" in name:
            return True

    if any(pattern in text for pattern in internal_patterns):
        # Avoid overclassifying external dependencies that merely mention spring-boot
        # in path. This is conservative: only classify as internal if group/name
        # or purl strongly suggests project-internal Spring Boot module.
        if group.startswith("org.springframework.boot") or purl.startswith(
            "pkg:maven/org.springframework.boot/"
        ):
            return True

    return False


def infer_component_role(row):
    if has_github_action_evidence(row):
        return "workflow_component"

    if looks_local_fixture_or_test_artifact(row):
        return "local_fixture_or_test_artifact"

    if looks_internal_module(row):
        return "internal_module"

    component_type = lower(row.get("component_type"))
    name = lower(row.get("name"))
    purl = lower(row.get("purl"))
    version = lower(row.get("version"))

    if component_type == "application":
        if "latest" in version or purl.endswith("@latest"):
            return "root_project"

    if purl.startswith(("pkg:npm/", "pkg:pypi/", "pkg:maven/")):
        return "external_dependency"

    ecosystem = normalize_ecosystem(row)
    if ecosystem in {"npm", "pypi", "maven"} and is_present(row.get("name")):
        return "external_dependency"

    if component_type in {"library", "framework"} and is_present(row.get("name")):
        return "external_dependency"

    return "unknown"


def infer_version_status(row):
    version = lower(row.get("version"))

    if is_missing(version):
        return "missing"

    placeholder_values = {
        "latest",
        "unknown",
        "undefined",
        "none",
        "null",
        "snapshot",
        "unspecified",
    }

    if version in placeholder_values:
        return "placeholder"

    if version.endswith("-snapshot"):
        # Snapshot is not necessarily invalid, but weaker than a released exact version.
        return "present"

    return "present"


def infer_version_missing_reason(row, component_role, version_status):
    if version_status == "present":
        return "not_missing"

    if component_role == "root_project":
        return "root_project_version_not_resolved"

    if component_role == "internal_module":
        return "internal_module_version_not_resolved"

    if component_role == "workflow_component":
        return "workflow_component_no_version"

    if component_role == "local_fixture_or_test_artifact":
        return "local_artifact_version_not_resolved"

    if version_status == "placeholder":
        return "placeholder_version"

    return "unknown"


def infer_purl_status(row):
    purl = clean(row.get("purl"))
    purl_l = purl.lower()

    if is_missing(purl):
        return "missing"

    if "@latest" in purl_l or purl_l.endswith("@unknown"):
        return "placeholder_version"

    if not purl_l.startswith("pkg:"):
        return "malformed"

    # Basic purl plausibility checks
    if purl_l.startswith("pkg:maven/"):
        rest = purl[10:]
        # Maven purl should usually have namespace/artifact, e.g. pkg:maven/group/artifact@version
        if "/" not in rest:
            return "malformed"

    if purl_l.startswith("pkg:npm/"):
        # pkg:npm/name or pkg:npm/%40scope/name
        if len(purl_l) <= len("pkg:npm/"):
            return "malformed"

    if purl_l.startswith("pkg:pypi/"):
        if len(purl_l) <= len("pkg:pypi/"):
            return "malformed"

    return "valid_or_plausible"


def infer_purl_issue(row, purl_status):
    purl = lower(row.get("purl"))
    issues = []

    if purl_status == "missing":
        issues.append("missing_purl")
    elif purl_status == "malformed":
        issues.append("malformed_structure")
    elif purl_status == "placeholder_version":
        issues.append("placeholder_version_in_purl")

    if purl.startswith("pkg:maven/"):
        rest = purl[len("pkg:maven/") :]
        if "/" not in rest:
            issues.append("missing_namespace_or_group")

    if not issues:
        return "none"

    return ";".join(sorted(set(issues)))


def infer_license_status(row):
    license_value = clean(row.get("license"))
    raw = lower(row.get("component_raw_json"))
    ext = lower(row.get("external_references_raw"))

    if is_present(license_value):
        if " or " in license_value.lower() or " and " in license_value.lower():
            return "present_in_expression"
        return "present_in_license_field"

    if '"expression"' in raw or "'expression'" in raw:
        return "present_in_expression"

    if "license" in raw and not is_missing(raw):
        return "present_elsewhere"

    if "license" in ext:
        return "present_in_external_reference"

    return "absent"


def infer_license_location(row, license_status):
    raw = lower(row.get("component_raw_json"))

    if license_status == "present_in_license_field":
        if '"id"' in raw:
            return "licenses.license.id"
        if '"name"' in raw:
            return "licenses.license.name"
        return "license_column"

    if license_status == "present_in_expression":
        return "licenses.expression"

    if license_status == "present_elsewhere":
        return "component_raw_json"

    if license_status == "present_in_external_reference":
        return "externalReferences"

    return "not_found"


def infer_license_format_status(row, license_status):
    license_value = clean(row.get("license"))

    if license_status == "absent":
        return "missing"

    if license_status == "present_in_expression":
        return "spdx_expression"

    if is_missing(license_value):
        return "uncertain"

    # Simple SPDX-like identifier pattern, not full SPDX validation
    if re.match(r"^[A-Za-z0-9\.\-\+]+$", license_value):
        return "spdx_id"

    if "http://" in license_value or "https://" in license_value:
        return "license_url_only"

    return "free_text"


def infer_repository_url_status(row):
    repository_url = clean(row.get("repository_url"))
    raw = lower(row.get("component_raw_json"))
    ext = lower(row.get("external_references_raw"))

    if is_present(repository_url):
        return "present_vcs_external_reference"

    if '"type":"vcs"' in raw or '"type": "vcs"' in raw:
        return "present_vcs_external_reference"

    if "repository" in raw or "scm" in raw:
        return "present_elsewhere"

    if "github.com" in raw and "registry.npmjs.org" not in raw:
        return "present_elsewhere"

    if "github.com" in ext and "registry.npmjs.org" not in ext:
        return "present_elsewhere"

    return "absent"


def infer_repository_url_location(row, repository_status):
    if repository_status == "present_vcs_external_reference":
        return "externalReferences.vcs"

    if repository_status == "present_elsewhere":
        return "component_raw_json"

    return "not_found"


def infer_hash_status(row):
    if is_present(row.get("hash_values")):
        return "present"
    return "absent"


def looks_like_exact_artifact_url(value):
    """
    Conservative check for an explicit distribution-artifact URL.

    The purpose is not to prove that the URL is correct; it is to avoid
    treating package+version identity alone as sufficient for hash repair.
    A hash is artifact-specific, so the SBOM must expose an explicit file
    identity before automatic hash repair is considered.
    """
    value = clean(value)
    if not value:
        return False

    # Remove query/fragment before checking the file name.
    base = value.split("#", 1)[0].split("?", 1)[0].lower().rstrip("/")

    artifact_suffixes = (
        ".jar",
        ".war",
        ".ear",
        ".zip",
        ".tgz",
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".whl",
        ".gem",
        ".nupkg",
    )

    return base.endswith(artifact_suffixes)


def infer_artifact_identity_status(row, ecosystem, hash_status):
    """
    Determine whether the original SBOM identifies a concrete artifact
    strongly enough for automatic hash repair.

    Exact package/version identity is deliberately NOT sufficient.
    """
    if hash_status != "absent":
        return "not_needed_hash_present"

    distribution_url = clean(row.get("distribution_url"))

    if looks_like_exact_artifact_url(distribution_url):
        return "exact_artifact_url_present"

    return "artifact_not_explicitly_identified"


def infer_distribution_url_status(row):
    if is_present(row.get("distribution_url")):
        return "present"

    raw = lower(row.get("component_raw_json"))
    ext = lower(row.get("external_references_raw"))

    if "distribution" in raw or "registry.npmjs.org" in raw or "files.pythonhosted.org" in raw:
        return "present"

    if "distribution" in ext or "registry.npmjs.org" in ext or "files.pythonhosted.org" in ext:
        return "present"

    return "absent"


def make_duplicate_keys(row):
    purl = clean(row.get("purl"))
    ecosystem = normalize_ecosystem(row)
    group = lower(row.get("group"))
    name = lower(row.get("name"))
    version = lower(row.get("version"))

    identity_key = f"purl::{purl}" if purl else f"namever::{ecosystem}|{group}|{name}|{version}"
    name_key = f"name::{ecosystem}|{group}|{name}"

    return identity_key, name_key


def infer_duplicate_status(row, identity_counts, name_version_counts, name_counts):
    purl = clean(row.get("purl"))
    ecosystem = normalize_ecosystem(row)
    group = lower(row.get("group"))
    name = lower(row.get("name"))
    version = lower(row.get("version"))

    identity_key, name_key = make_duplicate_keys(row)
    name_version_key = f"namever::{ecosystem}|{group}|{name}|{version}"

    if identity_counts[identity_key] > 1:
        if purl:
            return "duplicate_same_purl"
        return "duplicate_same_name_version"

    if name_version_counts[name_version_key] > 1:
        return "duplicate_same_name_version"

    if name_counts[name_key] > 1:
        return "duplicate_name_different_version"

    return "not_duplicate"


def infer_identity_status(row, component_role, version_status, purl_status):
    if component_role in {
        "internal_module",
        "local_fixture_or_test_artifact",
    }:
        return "not_applicable"

    if component_role == "workflow_component":
        if purl_status == "valid_or_plausible" and is_present(row.get("version")):
            return "clear_identity"
        return "partial_identity"

    if component_role == "root_project":
        if version_status in {"missing", "placeholder"}:
            return "partial_identity"
        return "clear_identity"

    name_present = is_present(row.get("name"))
    version_present = version_status == "present"

    if purl_status == "valid_or_plausible" and name_present and version_present:
        return "clear_identity"

    if name_present and version_present:
        return "partial_identity"

    if name_present and not version_present:
        return "partial_identity"

    if not name_present:
        return "missing_identity"

    return "ambiguous_identity"


def infer_repair_decision_and_actions(
    row,
    component_role,
    ecosystem,
    identity_status,
    version_status,
    purl_status,
    license_status,
    repository_status,
    hash_status,
    distribution_status,
    duplicate_status,
    artifact_identity_status,
):
    """
    Classify repair eligibility with field-specific abstention.

    `target_fields` contains ONLY fields allowed to proceed through the
    automatic repair pipeline. Fields that need human review are kept in
    `manual_review_fields` instead of downgrading the entire component.

    This is particularly important for hashes: an ambiguous hash must not
    suppress otherwise defensible license/repository/distribution repairs.
    """
    actions = []
    evidence_sources = []
    target_fields = []
    manual_review_fields = []
    manual_review_actions = []
    excluded_fields = []
    exclusion_reason = ""
    manual_review_reason = ""
    confidence_policy = ""
    matched_rule_ids = []

    def unique_join(values):
        return ";".join(sorted(set(v for v in values if v and v != "none"))) or "none"

    def decision_dict(
        repair_decision,
        repair_action,
        target_fields_value,
        evidence_source_value,
        confidence_policy_value,
        exclusion_reason_value="",
        manual_review_reason_value="",
        matched_rules_value="none",
        manual_fields_value="none",
        manual_actions_value="none",
        excluded_fields_value="none",
    ):
        return {
            "repair_decision": repair_decision,
            "repair_action": repair_action,
            "target_fields": target_fields_value,
            "manual_review_fields": manual_fields_value,
            "manual_review_actions": manual_actions_value,
            "excluded_fields": excluded_fields_value,
            "recommended_evidence_source": evidence_source_value,
            "confidence_policy": confidence_policy_value,
            "exclusion_reason": exclusion_reason_value,
            "manual_review_reason": manual_review_reason_value,
            "matched_rule_ids": matched_rules_value,
        }

    # ------------------------------------------------------------
    # Component types that genuinely remain outside registry repair.
    # ------------------------------------------------------------
    if component_role == "internal_module":
        return decision_dict(
            repair_decision="exclude_from_registry_repair",
            repair_action="exclude_internal_component",
            target_fields_value="none",
            evidence_source_value="local_project_evidence;manual_review",
            confidence_policy_value="none_for_registry_repair",
            exclusion_reason_value="internal_module",
            matched_rules_value="R7",
            excluded_fields_value="all_registry_based_fields",
        )

    if component_role == "local_fixture_or_test_artifact":
        return decision_dict(
            repair_decision="exclude_from_registry_repair",
            repair_action="exclude_internal_component",
            target_fields_value="none",
            evidence_source_value="local_project_evidence;manual_review",
            confidence_policy_value="none_for_registry_repair",
            exclusion_reason_value="local_fixture_or_test_artifact",
            matched_rules_value="R8",
            excluded_fields_value="all_registry_based_fields",
        )

    # ------------------------------------------------------------
    # Workflow components: field-specific abstention.
    #
    # We no longer discard the whole component. The current implementation
    # still has no GitHub-specific automatic retrieval adapter here, so
    # repairable-looking missing fields are retained for manual/source-
    # specific review rather than being auto-repaired.
    # ------------------------------------------------------------
    if component_role == "workflow_component":
        if version_status in {"missing", "placeholder"}:
            manual_review_fields.append("version")
        if purl_status in {"missing", "malformed", "placeholder_version"}:
            manual_review_fields.append("purl")
        if license_status == "absent":
            manual_review_fields.append("license")
        if repository_status == "absent":
            manual_review_fields.append("repository_url")
        if is_missing(row.get("supplier")):
            manual_review_fields.append("supplier")
        if distribution_status == "absent":
            manual_review_fields.append("distribution_url")
        if hash_status == "absent":
            manual_review_fields.append("hash_values")

        if manual_review_fields:
            return decision_dict(
                repair_decision="manual_review_required",
                repair_action="workflow_source_lookup;manual_review",
                target_fields_value="none",
                manual_fields_value=unique_join(manual_review_fields),
                manual_actions_value="github_repository;workflow_file;manual_review",
                evidence_source_value="github_repository;workflow_file;manual_review",
                confidence_policy_value="field_specific_manual_review",
                manual_review_reason_value="workflow_component_requires_source_specific_validation",
                matched_rules_value="R9",
            )

        return decision_dict(
            repair_decision="no_repair_needed",
            repair_action="no_repair_needed",
            target_fields_value="none",
            evidence_source_value="not_applicable",
            confidence_policy_value="not_applicable",
            matched_rules_value="R9",
        )

    if component_role == "root_project":
        manual_fields = []
        if version_status in {"missing", "placeholder"}:
            manual_fields.append("version")
        if purl_status in {"missing", "malformed", "placeholder_version"}:
            manual_fields.append("purl")
        if license_status == "absent":
            manual_fields.append("license")
        if repository_status == "absent":
            manual_fields.append("repository_url")
        if is_missing(row.get("supplier")):
            manual_fields.append("supplier")
        if distribution_status == "absent":
            manual_fields.append("distribution_url")
        if hash_status == "absent":
            manual_fields.append("hash_values")

        return decision_dict(
            repair_decision="manual_review_required",
            repair_action="project_metadata_lookup;manual_review",
            target_fields_value="none",
            manual_fields_value=unique_join(manual_fields),
            manual_actions_value="project_metadata_lookup;manual_review",
            evidence_source_value="github_repository;manifest;manual_review",
            confidence_policy_value="medium_if_project_metadata_clear",
            manual_review_reason_value="root_project_component",
            matched_rules_value="R10",
        )

    # ------------------------------------------------------------
    # Weak identity remains component-wide because safe source lookup
    # cannot be established until the identity problem is resolved.
    # ------------------------------------------------------------
    if identity_status in {"ambiguous_identity", "missing_identity"}:
        return decision_dict(
            repair_decision="manual_review_required",
            repair_action="manual_review",
            target_fields_value="none",
            manual_fields_value="all_missing_fields",
            manual_actions_value="identity_resolution;manual_review",
            evidence_source_value="manual_review;manifest;repository_metadata",
            confidence_policy_value="low_until_identity_resolved",
            manual_review_reason_value="ambiguous_or_missing_identity",
            matched_rules_value="R20",
        )

    if version_status in {"missing", "placeholder"}:
        return decision_dict(
            repair_decision="manual_review_required",
            repair_action="version_lookup;manual_review",
            target_fields_value="none",
            manual_fields_value="purl;version",
            manual_actions_value="version_lookup;manual_review",
            evidence_source_value="manifest;repository_metadata;manual_review",
            confidence_policy_value="low_until_version_confirmed",
            manual_review_reason_value="missing_or_placeholder_version",
            matched_rules_value="R6",
        )

    if purl_status in {"malformed", "placeholder_version"}:
        return decision_dict(
            repair_decision="manual_review_required",
            repair_action="purl_correction;manual_review",
            target_fields_value="none",
            manual_fields_value="purl",
            manual_actions_value="purl_correction;manual_review",
            evidence_source_value="manifest;package_registry;manual_review",
            confidence_policy_value="medium_or_low",
            manual_review_reason_value="malformed_or_placeholder_purl",
            matched_rules_value="R5",
        )

    # ------------------------------------------------------------
    # Duplicates are audit flags, not automatic blockers.
    # ------------------------------------------------------------
    if duplicate_status in {"duplicate_same_purl", "duplicate_same_name_version"}:
        actions.append("duplicate_resolution")
        evidence_sources.append("sbom_internal_evidence")
        matched_rule_ids.append("R18")

    if duplicate_status == "duplicate_name_different_version":
        actions.append("duplicate_analysis")
        evidence_sources.append("sbom_internal_evidence")
        matched_rule_ids.append("R19")

    # ------------------------------------------------------------
    # Clear/partial external dependency.
    # ------------------------------------------------------------
    if component_role == "external_dependency" and identity_status in {
        "clear_identity",
        "partial_identity",
    }:
        if ecosystem == "npm":
            evidence_sources.extend(["npm_registry", "spdx_license_list"])
            matched_rule_ids.append("R1")
        elif ecosystem == "pypi":
            evidence_sources.extend(["pypi_registry", "spdx_license_list"])
            matched_rule_ids.append("R2")
        elif ecosystem == "maven":
            evidence_sources.extend(["maven_central", "pom_xml", "spdx_license_list"])
            matched_rule_ids.append("R3")
        else:
            evidence_sources.extend(["package_registry", "spdx_license_list"])

        if purl_status == "missing":
            actions.append("purl_generation")
            target_fields.append("purl")
            matched_rule_ids.append("R4")

        if license_status == "present_in_expression":
            actions.append("license_normalization")
            target_fields.append("license")
            evidence_sources.extend(["sbom_internal_evidence", "spdx_license_list"])
            matched_rule_ids.append("R11")

        if license_status == "absent":
            actions.extend(["license_lookup", "license_normalization"])
            target_fields.append("license")
            matched_rule_ids.append("R12")

        if repository_status == "absent":
            actions.append("repository_lookup")
            target_fields.append("repository_url")
            matched_rule_ids.append("R13")

        if distribution_status == "present" and repository_status == "absent":
            matched_rule_ids.append("R14")

        if is_missing(row.get("supplier")):
            # Keep the historical candidate generation behavior here.
            # Supplier semantics are handled conservatively downstream.
            actions.append("supplier_lookup")
            target_fields.append("supplier")
            matched_rule_ids.append("R15")

        if distribution_status == "absent":
            actions.append("distribution_url_lookup")
            target_fields.append("distribution_url")
            matched_rule_ids.append("R21")

        # --------------------------------------------------------
        # Revised hash rule.
        #
        # Package+version identity is not enough. Hash repair is automatic
        # only when the ORIGINAL SBOM explicitly identifies the concrete
        # distribution artifact. Otherwise only the hash field abstains;
        # other fields remain eligible for automatic repair.
        # --------------------------------------------------------
        if hash_status == "absent":
            if artifact_identity_status == "exact_artifact_url_present":
                actions.append("hash_lookup_exact_artifact")
                target_fields.append("hash_values")
                matched_rule_ids.append("R16")
            else:
                manual_review_fields.append("hash_values")
                manual_review_actions.append("resolve_exact_artifact_before_hash_lookup")
                matched_rule_ids.append("R17")

        actions = sorted(set(actions))
        evidence_sources = sorted(set(evidence_sources))
        target_fields = sorted(set(target_fields))
        manual_review_fields = sorted(set(manual_review_fields))
        manual_review_actions = sorted(set(manual_review_actions))
        matched_rule_ids = sorted(set(matched_rule_ids))

        # Only duplicate-analysis actions with no actual target field do not
        # justify registry retrieval by themselves.
        real_auto_fields = [field for field in target_fields if field != "none"]

        if real_auto_fields:
            if ecosystem == "maven":
                confidence_policy = "high_if_exact_group_artifact_version_match;hash_requires_exact_artifact"
            elif ecosystem in {"npm", "pypi"}:
                confidence_policy = "high_if_exact_package_and_version_match;hash_requires_exact_artifact"
            else:
                confidence_policy = "medium_if_identity_clear;hash_requires_exact_artifact"

            if manual_review_fields:
                confidence_policy += ";manual_review_for=" + ",".join(manual_review_fields)

            return decision_dict(
                repair_decision="auto_repair_candidate",
                repair_action=unique_join(actions),
                target_fields_value=unique_join(real_auto_fields),
                manual_fields_value=unique_join(manual_review_fields),
                manual_actions_value=unique_join(manual_review_actions),
                evidence_source_value=unique_join(evidence_sources),
                confidence_policy_value=confidence_policy,
                manual_review_reason_value=(
                    "field_specific_abstention" if manual_review_fields else ""
                ),
                matched_rules_value=unique_join(matched_rule_ids),
            )

        if manual_review_fields:
            return decision_dict(
                repair_decision="manual_review_required",
                repair_action=unique_join(manual_review_actions),
                target_fields_value="none",
                manual_fields_value=unique_join(manual_review_fields),
                manual_actions_value=unique_join(manual_review_actions),
                evidence_source_value=unique_join(evidence_sources),
                confidence_policy_value="manual_review_until_exact_artifact_resolved",
                manual_review_reason_value="field_specific_abstention",
                matched_rules_value=unique_join(matched_rule_ids),
            )

        # Duplicate flags alone are not repairs.
        return decision_dict(
            repair_decision="no_repair_needed",
            repair_action="no_repair_needed",
            target_fields_value="none",
            evidence_source_value="not_applicable",
            confidence_policy_value="not_applicable",
            matched_rules_value=unique_join(matched_rule_ids),
        )

    # Fallback
    return decision_dict(
        repair_decision="manual_review_required",
        repair_action="manual_review",
        target_fields_value="none",
        manual_fields_value="all_missing_fields",
        manual_actions_value="manual_review",
        evidence_source_value="manual_review",
        confidence_policy_value="low",
        manual_review_reason_value="fallback_uncertain_component",
        matched_rules_value="fallback",
    )


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Missing input file: {INPUT_FILE}")

    with INPUT_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        input_fieldnames = reader.fieldnames or []
        rows = list(reader)

    print(f"Loaded component rows: {len(rows)}")

    identity_counts = Counter()
    name_version_counts = Counter()
    name_counts = Counter()

    for row in rows:
        identity_key, name_key = make_duplicate_keys(row)
        ecosystem = normalize_ecosystem(row)
        group = lower(row.get("group"))
        name = lower(row.get("name"))
        version = lower(row.get("version"))
        name_version_key = f"namever::{ecosystem}|{group}|{name}|{version}"

        identity_counts[identity_key] += 1
        name_counts[name_key] += 1
        name_version_counts[name_version_key] += 1

    output_rows = []
    classified_at = datetime.now(timezone.utc).isoformat()

    for row in rows:
        ecosystem = normalize_ecosystem(row)

        component_role = infer_component_role(row)
        version_status = infer_version_status(row)
        version_missing_reason = infer_version_missing_reason(
            row, component_role, version_status
        )
        purl_status = infer_purl_status(row)
        purl_issue = infer_purl_issue(row, purl_status)
        license_status = infer_license_status(row)
        license_location = infer_license_location(row, license_status)
        license_format_status = infer_license_format_status(row, license_status)
        repository_status = infer_repository_url_status(row)
        repository_location = infer_repository_url_location(row, repository_status)
        hash_status = infer_hash_status(row)
        distribution_status = infer_distribution_url_status(row)
        artifact_identity_status = infer_artifact_identity_status(
            row, ecosystem, hash_status
        )
        duplicate_status = infer_duplicate_status(
            row, identity_counts, name_version_counts, name_counts
        )
        identity_status = infer_identity_status(
            row, component_role, version_status, purl_status
        )

        decision = infer_repair_decision_and_actions(
            row=row,
            component_role=component_role,
            ecosystem=ecosystem,
            identity_status=identity_status,
            version_status=version_status,
            purl_status=purl_status,
            license_status=license_status,
            repository_status=repository_status,
            hash_status=hash_status,
            distribution_status=distribution_status,
            duplicate_status=duplicate_status,
            artifact_identity_status=artifact_identity_status,
        )

        identity_key, name_key = make_duplicate_keys(row)

        out = dict(row)
        out["component_id"] = get_component_id(row)
        out["project_ecosystem_label"] = project_ecosystem_label(row)
        out["ecosystem_normalized"] = ecosystem
        out["component_role_predicted"] = component_role
        out["identity_status_predicted"] = identity_status
        out["version_status_predicted"] = version_status
        out["version_missing_reason_predicted"] = version_missing_reason
        out["purl_status_predicted"] = purl_status
        out["purl_issue_predicted"] = purl_issue
        out["license_presence_status_predicted"] = license_status
        out["license_location_predicted"] = license_location
        out["license_format_status_predicted"] = license_format_status
        out["repository_url_status_predicted"] = repository_status
        out["repository_url_location_predicted"] = repository_location
        out["hash_status_predicted"] = hash_status
        out["distribution_url_status_predicted"] = distribution_status
        out["artifact_identity_status_predicted"] = artifact_identity_status
        out["duplicate_status_predicted"] = duplicate_status
        out["duplicate_identity_key"] = identity_key
        out["duplicate_identity_count"] = identity_counts[identity_key]
        out["duplicate_name_key"] = name_key
        out["duplicate_name_count"] = name_counts[name_key]
        out["repair_decision_predicted"] = decision["repair_decision"]
        out["repair_action_predicted"] = decision["repair_action"]
        out["target_fields_predicted"] = decision["target_fields"]
        out["manual_review_fields_predicted"] = decision.get(
            "manual_review_fields", "none"
        )
        out["manual_review_actions_predicted"] = decision.get(
            "manual_review_actions", "none"
        )
        out["excluded_fields_predicted"] = decision.get(
            "excluded_fields", "none"
        )
        out["recommended_evidence_source_predicted"] = decision[
            "recommended_evidence_source"
        ]
        out["confidence_policy_predicted"] = decision["confidence_policy"]
        out["exclusion_reason"] = decision["exclusion_reason"]
        out["manual_review_reason"] = decision["manual_review_reason"]
        out["matched_rule_ids"] = decision["matched_rule_ids"]
        out["classified_at"] = classified_at

        output_rows.append(out)

    added_fields = [
        "component_id",
        "project_ecosystem_label",
        "ecosystem_normalized",
        "component_role_predicted",
        "identity_status_predicted",
        "version_status_predicted",
        "version_missing_reason_predicted",
        "purl_status_predicted",
        "purl_issue_predicted",
        "license_presence_status_predicted",
        "license_location_predicted",
        "license_format_status_predicted",
        "repository_url_status_predicted",
        "repository_url_location_predicted",
        "hash_status_predicted",
        "distribution_url_status_predicted",
        "artifact_identity_status_predicted",
        "duplicate_status_predicted",
        "duplicate_identity_key",
        "duplicate_identity_count",
        "duplicate_name_key",
        "duplicate_name_count",
        "repair_decision_predicted",
        "repair_action_predicted",
        "target_fields_predicted",
        "manual_review_fields_predicted",
        "manual_review_actions_predicted",
        "excluded_fields_predicted",
        "recommended_evidence_source_predicted",
        "confidence_policy_predicted",
        "exclusion_reason",
        "manual_review_reason",
        "matched_rule_ids",
        "classified_at",
    ]

    output_fieldnames = input_fieldnames[:]
    for field in added_fields:
        if field not in output_fieldnames:
            output_fieldnames.append(field)

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=output_fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"Saved classified components to: {OUTPUT_FILE}")

    write_summary(output_rows)
    write_summary_by_ecosystem_tool(output_rows)

    print(f"Saved summary to: {SUMMARY_FILE}")
    print(f"Saved ecosystem/tool summary to: {SUMMARY_BY_ECOSYSTEM_TOOL_FILE}")


def write_summary(rows):
    total = len(rows)

    counters = {
        "repair_decision_predicted": Counter(),
        "component_role_predicted": Counter(),
        "identity_status_predicted": Counter(),
        "version_status_predicted": Counter(),
        "purl_status_predicted": Counter(),
        "license_presence_status_predicted": Counter(),
        "repository_url_status_predicted": Counter(),
        "hash_status_predicted": Counter(),
        "distribution_url_status_predicted": Counter(),
        "artifact_identity_status_predicted": Counter(),
        "duplicate_status_predicted": Counter(),
    }

    for row in rows:
        for field, counter in counters.items():
            counter[row[field]] += 1

    with SUMMARY_FILE.open("w", newline="", encoding="utf-8") as f:
        fieldnames = ["category", "label", "count", "percentage"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for category, counter in counters.items():
            for label, count in sorted(counter.items()):
                pct = (count / total * 100) if total else 0
                writer.writerow(
                    {
                        "category": category,
                        "label": label,
                        "count": count,
                        "percentage": f"{pct:.2f}",
                    }
                )


def write_summary_by_ecosystem_tool(rows):
    grouped = defaultdict(list)

    for row in rows:
        key = (
            row.get("ecosystem_normalized", ""),
            row.get("tool", ""),
            row.get("repair_decision_predicted", ""),
        )
        grouped[key].append(row)

    totals = Counter((row.get("ecosystem_normalized", ""), row.get("tool", "")) for row in rows)

    with SUMMARY_BY_ECOSYSTEM_TOOL_FILE.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "ecosystem",
            "tool",
            "repair_decision",
            "count",
            "percentage_within_ecosystem_tool",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for (ecosystem, tool, decision), group_rows in sorted(grouped.items()):
            total = totals[(ecosystem, tool)]
            count = len(group_rows)
            pct = (count / total * 100) if total else 0

            writer.writerow(
                {
                    "ecosystem": ecosystem,
                    "tool": tool,
                    "repair_decision": decision,
                    "count": count,
                    "percentage_within_ecosystem_tool": f"{pct:.2f}",
                }
            )


if __name__ == "__main__":
    main()
