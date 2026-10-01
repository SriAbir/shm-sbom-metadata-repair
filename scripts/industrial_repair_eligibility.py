#!/usr/bin/env python3

import csv
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

INPUT_DIR = Path("CompanyData")

OUTPUT_FILE = INPUT_DIR / "xxx_component_repair_candidates.csv"
SUMMARY_FILE = INPUT_DIR / "xxx_component_repair_candidate_summary.csv"
SUMMARY_BY_ECOSYSTEM_TOOL_FILE = (
    INPUT_DIR / "xxx_component_repair_candidate_summary_by_ecosystem_tool.csv"
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
    ecosystem = lower(row.get("ecosystem"))
    purl = clean(row.get("purl"))

    if ecosystem:
        return ecosystem

    inferred = infer_ecosystem_from_purl(purl)
    if inferred:
        return inferred

    return ""


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
):
    actions = []
    evidence_sources = []
    target_fields = []
    exclusion_reason = ""
    manual_review_reason = ""
    confidence_policy = ""

    # Exclusion rules first
    if component_role == "internal_module":
        return {
            "repair_decision": "exclude_from_registry_repair",
            "repair_action": "exclude_internal_component",
            "target_fields": "none",
            "recommended_evidence_source": "local_project_evidence;manual_review",
            "confidence_policy": "none_for_registry_repair",
            "exclusion_reason": "internal_module",
            "manual_review_reason": "",
            "matched_rule_ids": "R7",
        }

    if component_role == "local_fixture_or_test_artifact":
        return {
            "repair_decision": "exclude_from_registry_repair",
            "repair_action": "exclude_internal_component",
            "target_fields": "none",
            "recommended_evidence_source": "local_project_evidence;manual_review",
            "confidence_policy": "none_for_registry_repair",
            "exclusion_reason": "local_fixture_or_test_artifact",
            "manual_review_reason": "",
            "matched_rule_ids": "R8",
        }

    if component_role == "workflow_component":
        return {
            "repair_decision": "exclude_from_registry_repair",
            "repair_action": "exclude_workflow_component",
            "target_fields": "none",
            "recommended_evidence_source": "github_repository;workflow_file;manual_review",
            "confidence_policy": "none_for_package_registry_repair",
            "exclusion_reason": "workflow_component",
            "manual_review_reason": "",
            "matched_rule_ids": "R9",
        }

    if component_role == "root_project":
        return {
            "repair_decision": "manual_review_required",
            "repair_action": "project_metadata_lookup;manual_review",
            "target_fields": "version;license;repository_url;supplier",
            "recommended_evidence_source": "github_repository;manifest;manual_review",
            "confidence_policy": "medium_if_project_metadata_clear",
            "exclusion_reason": "",
            "manual_review_reason": "root_project_component",
            "matched_rule_ids": "R10",
        }

    # Manual review rules for weak identity
    if identity_status in {"ambiguous_identity", "missing_identity"}:
        return {
            "repair_decision": "manual_review_required",
            "repair_action": "manual_review",
            "target_fields": "none",
            "recommended_evidence_source": "manual_review;manifest;repository_metadata",
            "confidence_policy": "low_until_identity_resolved",
            "exclusion_reason": "",
            "manual_review_reason": "ambiguous_or_missing_identity",
            "matched_rule_ids": "R20",
        }

    if version_status in {"missing", "placeholder"}:
        return {
            "repair_decision": "manual_review_required",
            "repair_action": "version_lookup;manual_review",
            "target_fields": "version;purl",
            "recommended_evidence_source": "manifest;repository_metadata;manual_review",
            "confidence_policy": "low_until_version_confirmed",
            "exclusion_reason": "",
            "manual_review_reason": "missing_or_placeholder_version",
            "matched_rule_ids": "R6",
        }

    if purl_status in {"malformed", "placeholder_version"}:
        return {
            "repair_decision": "manual_review_required",
            "repair_action": "purl_correction;manual_review",
            "target_fields": "purl",
            "recommended_evidence_source": "manifest;package_registry;manual_review",
            "confidence_policy": "medium_or_low",
            "exclusion_reason": "",
            "manual_review_reason": "malformed_or_placeholder_purl",
            "matched_rule_ids": "R5",
        }

    if duplicate_status in {"duplicate_same_purl", "duplicate_same_name_version"}:
        # Do not block metadata repair entirely, but flag for review.
        actions.append("duplicate_resolution")
        evidence_sources.append("sbom_internal_evidence")
        target_fields.append("none")

    if duplicate_status == "duplicate_name_different_version":
        actions.append("duplicate_analysis")
        evidence_sources.append("sbom_internal_evidence")
        target_fields.append("none")

    matched_rule_ids = []

    # Main SHM study scope: npm, PyPI, and Maven only.
    # Industrial Black Duck components from other ecosystems are retained
    # in the output but are not automatically repaired by package-registry rules.
    if component_role == "external_dependency" and ecosystem not in {"npm", "pypi", "maven"}:
        return {
            "repair_decision": "manual_review_required",
            "repair_action": "manual_review",
            "target_fields": "none",
            "recommended_evidence_source": "ecosystem_specific_source;manual_review",
            "confidence_policy": "out_of_scope_for_main_shm_registry_rules",
            "exclusion_reason": "",
            "manual_review_reason": "unsupported_ecosystem_for_main_shm",
            "matched_rule_ids": "industrial_scope_guard",
        }

    # Clear external dependency rules
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
            actions.append("supplier_lookup")
            target_fields.append("supplier")
            matched_rule_ids.append("R15")

        if distribution_status == "absent":
            actions.append("distribution_url_lookup")
            target_fields.append("distribution_url")
            matched_rule_ids.append("R21")

        if hash_status == "absent":
            if ecosystem == "maven":
                actions.append("hash_lookup")
                target_fields.append("hash_values")
                matched_rule_ids.append("R16")
            elif ecosystem in {"npm", "pypi"}:
                # Keep as manual review because exact artifact matching is required.
                return {
                    "repair_decision": "manual_review_required",
                    "repair_action": "hash_lookup;manual_review",
                    "target_fields": "hash_values",
                    "recommended_evidence_source": f"{ecosystem}_registry",
                    "confidence_policy": "medium_or_high_only_with_exact_artifact_url",
                    "exclusion_reason": "",
                    "manual_review_reason": "hash_absent_for_npm_or_pypi_requires_exact_artifact",
                    "matched_rule_ids": "R17",
                }

        actions = sorted(set(actions))
        evidence_sources = sorted(set(evidence_sources))
        target_fields = sorted(set(target_fields))
        matched_rule_ids = sorted(set(matched_rule_ids))

        if not actions:
            return {
                "repair_decision": "no_repair_needed",
                "repair_action": "no_repair_needed",
                "target_fields": "none",
                "recommended_evidence_source": "not_applicable",
                "confidence_policy": "not_applicable",
                "exclusion_reason": "",
                "manual_review_reason": "",
                "matched_rule_ids": "none",
            }

        if ecosystem == "maven":
            confidence_policy = "high_if_exact_group_artifact_version_match"
        elif ecosystem in {"npm", "pypi"}:
            confidence_policy = "high_if_exact_package_and_version_match"
        else:
            confidence_policy = "medium_if_identity_clear"

        return {
            "repair_decision": "auto_repair_candidate",
            "repair_action": ";".join(actions),
            "target_fields": ";".join(target_fields),
            "recommended_evidence_source": ";".join(evidence_sources),
            "confidence_policy": confidence_policy,
            "exclusion_reason": "",
            "manual_review_reason": "",
            "matched_rule_ids": ";".join(matched_rule_ids),
        }

    # Fallback
    return {
        "repair_decision": "manual_review_required",
        "repair_action": "manual_review",
        "target_fields": "none",
        "recommended_evidence_source": "manual_review",
        "confidence_policy": "low",
        "exclusion_reason": "",
        "manual_review_reason": "fallback_uncertain_component",
        "matched_rule_ids": "fallback",
    }



# ============================================================
# Industrial CycloneDX extraction
# ============================================================

def _extract_license_from_component(component):
    licenses = component.get("licenses", [])
    if not isinstance(licenses, list):
        return ""
    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        expression = entry.get("expression")
        if is_present(expression):
            return clean(expression)
        lic = entry.get("license")
        if isinstance(lic, dict):
            for key in ("id", "name"):
                if is_present(lic.get(key)):
                    return clean(lic.get(key))
    return ""


def _extract_supplier_from_component(component):
    supplier = component.get("supplier")
    if isinstance(supplier, dict):
        if is_present(supplier.get("name")):
            return clean(supplier.get("name"))
        if is_present(supplier.get("url")):
            return clean(supplier.get("url"))
        if is_present(supplier.get("contact")):
            return clean(supplier.get("contact"))
        return ""
    return clean(supplier)


def _extract_external_reference(component, wanted_type):
    refs = component.get("externalReferences", [])
    if not isinstance(refs, list):
        return ""
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if lower(ref.get("type")) == wanted_type and is_present(ref.get("url")):
            return clean(ref.get("url"))
    return ""


def _extract_hash_values_from_component(component):
    hashes = component.get("hashes", [])
    if not isinstance(hashes, list):
        return ""
    values = []
    for h in hashes:
        if not isinstance(h, dict):
            continue
        content = clean(h.get("content"))
        alg = clean(h.get("alg"))
        if content:
            values.append(f"{alg}:{content}" if alg else content)
    return ";".join(values)


def _infer_ecosystem_from_filename_or_purl(path, purl):
    inferred = infer_ecosystem_from_purl(purl)
    if inferred:
        return inferred

    p = lower(purl)
    if p.startswith("pkg:cargo/"):
        return "cargo"
    if p.startswith("pkg:nuget/"):
        return "nuget"
    if p.startswith("pkg:generic/"):
        return "generic"

    # Black Duck industrial SBOMs may contain components outside the
    # npm/PyPI/Maven scope of the main SHM experiment.
    return "unknown"


def load_anonymous_component_rows():
    if not INPUT_DIR.exists():
        raise FileNotFoundError(f"Missing input directory: {INPUT_DIR}")

    sbom_files = sorted(INPUT_DIR.glob("*.json"))
    if not sbom_files:
        raise FileNotFoundError(f"No CycloneDX JSON SBOMs found in: {INPUT_DIR}")

    rows = []
    for sbom_path in sbom_files:
        print(f"Reading SBOM: {sbom_path}")
        with sbom_path.open(encoding="utf-8") as f:
            bom = json.load(f)

        components = bom.get("components", []) or []
        if not isinstance(components, list):
            print(f"  WARNING: components is not a list in {sbom_path.name}")
            continue

        for idx, component in enumerate(components):
            if not isinstance(component, dict):
                continue

            purl = clean(component.get("purl"))
            refs = component.get("externalReferences", []) or []
            props = component.get("properties", []) or []

            row = {
                "project_id": sbom_path.stem,
                "tool": "blackduck",
                "ecosystem": _infer_ecosystem_from_filename_or_purl(sbom_path, purl),
                "sbom_path": str(sbom_path),
                "component_index": str(idx),
                "component_type": clean(component.get("type")),
                "bom_ref": clean(component.get("bom-ref")),
                "group": clean(component.get("group")),
                "name": clean(component.get("name")),
                "version": clean(component.get("version")),
                "purl": purl,
                "scope": clean(component.get("scope")),
                "license": _extract_license_from_component(component),
                "supplier": _extract_supplier_from_component(component),
                "repository_url": _extract_external_reference(component, "vcs"),
                "website_url": _extract_external_reference(component, "website"),
                "distribution_url": _extract_external_reference(component, "distribution"),
                "issue_tracker_url": _extract_external_reference(component, "issue-tracker"),
                "hash_values": _extract_hash_values_from_component(component),
                "external_references_raw": json.dumps(refs, ensure_ascii=False),
                "component_raw_json": json.dumps(component, ensure_ascii=False),
                "properties_raw": json.dumps(props, ensure_ascii=False),
            }
            rows.append(row)

        print(f"  Components extracted: {len(components)}")

    return rows


def main():
    rows = load_anonymous_component_rows()
    if not rows:
        print("No component rows extracted.")
        return

    input_fieldnames = list(rows[0].keys())
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
        )

        identity_key, name_key = make_duplicate_keys(row)

        out = dict(row)
        out["component_id"] = get_component_id(row)
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
        out["duplicate_status_predicted"] = duplicate_status
        out["duplicate_identity_key"] = identity_key
        out["duplicate_identity_count"] = identity_counts[identity_key]
        out["duplicate_name_key"] = name_key
        out["duplicate_name_count"] = name_counts[name_key]
        out["repair_decision_predicted"] = decision["repair_decision"]
        out["repair_action_predicted"] = decision["repair_action"]
        out["target_fields_predicted"] = decision["target_fields"]
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
        "duplicate_status_predicted",
        "duplicate_identity_key",
        "duplicate_identity_count",
        "duplicate_name_key",
        "duplicate_name_count",
        "repair_decision_predicted",
        "repair_action_predicted",
        "target_fields_predicted",
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

    INPUT_DIR.mkdir(parents=True, exist_ok=True)

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
