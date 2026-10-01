#!/usr/bin/env python3

import csv
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

CANDIDATES_FILE = Path("data/component_repair_candidates.csv")
EVIDENCE_FILE = Path("data/component_evidence_summary.csv")

REPAIR_PLAN_FILE = Path("data/component_repair_plan.csv")
PROVENANCE_FILE = Path("data/component_repair_provenance.csv")
FIELD_DECISIONS_FILE = Path("data/component_field_repair_decisions.csv")
ENRICHED_PREVIEW_FILE = Path("data/component_metadata_enriched_preview.csv")
SUMMARY_FILE = Path("data/repair_plan_summary.csv")
SUMMARY_BY_FIELD_FILE = Path("data/repair_plan_summary_by_field.csv")
SUMMARY_BY_ECOSYSTEM_FILE = Path("data/repair_plan_summary_by_ecosystem.csv")
FIELD_DECISION_SUMMARY_FILE = Path("data/component_field_repair_decision_summary.csv")

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

REPAIRABLE_FIELDS = [
    "license",
    "repository_url",
    "supplier",
    "distribution_url",
    "hash_values",
]

ALL_FIELD_MARKERS = {
    "all_missing_fields",
    "all_registry_based_fields",
    "all_fields",
}

TRUE_VALUES = {"true", "1", "yes", "y"}


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
    if value == "":
        return True
    return value.lower() in MISSING_VALUES


def is_present(value):
    return not is_missing(value)


def bool_text(value):
    return "true" if bool(value) else "false"


def is_true(value):
    return lower(value) in TRUE_VALUES


def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(f"Missing input file: {path}")

    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader), reader.fieldnames or []


def write_csv(path, rows, fieldnames=None):
    path.parent.mkdir(parents=True, exist_ok=True)

    if fieldnames is None:
        if rows:
            fieldnames = list(rows[0].keys())
        else:
            fieldnames = []

    with path.open("w", newline="", encoding="utf-8") as f:
        if not fieldnames:
            return
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_field_spec(value):
    value = clean(value)
    if not value or lower(value) == "none":
        return set()
    return {
        item.strip()
        for item in value.split(";")
        if item.strip() and lower(item) != "none"
    }


def field_marked(field, field_spec):
    tokens = parse_field_spec(field_spec)
    if tokens.intersection(ALL_FIELD_MARKERS):
        return True
    return field in tokens


def evidence_key(row):
    return (
        clean(row.get("component_id")),
        clean(row.get("project_id")),
        clean(row.get("tool")),
        clean(row.get("sbom_path")),
        clean(row.get("component_index")),
    )


def candidate_key(row):
    return (
        clean(row.get("component_id")),
        clean(row.get("project_id")),
        clean(row.get("tool")),
        clean(row.get("sbom_path")),
        clean(row.get("component_index")),
    )


def build_evidence_index(evidence_rows):
    index = {}

    for row in evidence_rows:
        index[evidence_key(row)] = row

    return index


def base_evidence_acceptable(row):
    """
    Component-identity/retrieval gate shared by automatic fields.

    This is deliberately only a base gate. Field-specific semantic checks
    are applied separately in field_evidence_allowed().
    """
    if row is None:
        return False, "no_external_metadata_record"

    status = lower(row.get("evidence_status"))
    confidence = lower(row.get("evidence_confidence"))
    exact_version = lower(row.get("evidence_exact_version_match"))

    if status != "success":
        return False, f"retrieval_status_{status or 'missing'}"

    if exact_version not in TRUE_VALUES:
        return False, "exact_version_not_established"

    if confidence not in {"high", "medium"}:
        return False, f"retrieval_confidence_{confidence or 'missing'}"

    return True, "base_metadata_acceptable"


def evidence_value_for_field(evidence_row, field):
    mapping = {
        "license": "evidence_license",
        "repository_url": "evidence_repository_url",
        "supplier": "evidence_supplier",
        "distribution_url": "evidence_distribution_url",
        "hash_values": "evidence_hash_values",
    }

    evidence_field = mapping[field]
    return clean(evidence_row.get(evidence_field))


def evidence_source_for_field(evidence_row, field):
    source = clean(evidence_row.get("evidence_source"))

    if field == "license" and source:
        return source + ";spdx_license_normalization_pending"

    return source


def evidence_reference_for_field(evidence_row, field):
    if field == "hash_values":
        return (
            clean(evidence_row.get("evidence_artifact_url"))
            or clean(evidence_row.get("evidence_input_artifact_url"))
            or clean(evidence_row.get("evidence_registry_url"))
        )

    return clean(evidence_row.get("evidence_registry_url"))


def normalize_license_value(value):
    value = clean(value)

    if not value:
        return ""

    replacements = {
        "apache license 2.0": "Apache-2.0",
        "apache 2.0": "Apache-2.0",
        "apache software license": "Apache-2.0",
        "mit license": "MIT",
        "bsd license": "BSD",
        "bsd-3-clause license": "BSD-3-Clause",
        "bsd 3-clause license": "BSD-3-Clause",
    }

    key = value.lower().strip()

    if key in replacements:
        return replacements[key]

    return value


def normalize_repository_url(value):
    value = clean(value)

    if value.startswith("git+"):
        value = value[len("git+") :]

    if value.endswith(".git"):
        value = value[:-4]

    return value


def normalize_supplier(value):
    value = clean(value)

    # Supplier role semantics are validated later. At this stage we retain
    # the retrieved party value and its role provenance without promoting
    # the role itself to a semantic acceptance decision.
    if value.lower() in {"unknown", "none", "n/a", "na"}:
        return ""

    return value


def normalize_distribution_url(value):
    return clean(value)


def normalize_hash_values(value):
    return clean(value)


def normalize_field_value(field, value):
    if field == "license":
        return normalize_license_value(value)

    if field == "repository_url":
        return normalize_repository_url(value)

    if field == "supplier":
        return normalize_supplier(value)

    if field == "distribution_url":
        return normalize_distribution_url(value)

    if field == "hash_values":
        return normalize_hash_values(value)

    return clean(value)


def field_evidence_allowed(candidate_row, evidence_row, field):
    """
    Apply field-specific semantic gates after the base metadata gate.

    The eligibility classifier decides which fields may be attempted.
    This function only checks whether the retrieved metadata is suitable
    for the specific field being proposed.
    """
    if evidence_row is None:
        return False, "no_external_metadata_record"

    if field == "repository_url":
        repository_value = clean(evidence_row.get("evidence_repository_url"))
        distribution_value = clean(evidence_row.get("evidence_distribution_url"))

        if not repository_value:
            return False, "repository_metadata_missing"

        if repository_value == distribution_value:
            return False, "repository_equals_distribution_url"

    if field == "hash_values":
        # Defense in depth: even if the classifier marks hash_values as an
        # automatic target, the retrieval stage must independently confirm
        # that the digest belongs to the exact identified artifact.
        if not is_true(evidence_row.get("evidence_hash_usable_for_auto_repair")):
            return False, "hash_not_usable_for_auto_repair"

        if not is_true(evidence_row.get("evidence_artifact_match")):
            return False, "exact_artifact_match_not_established"

        if is_missing(evidence_row.get("evidence_hash_values")):
            return False, "exact_artifact_hash_missing"

    return True, "field_metadata_acceptable"


def repair_method_for_field(field):
    methods = {
        "license": "registry_license_lookup",
        "repository_url": "registry_repository_lookup",
        "supplier": "registry_party_lookup",
        "distribution_url": "registry_distribution_lookup",
        "hash_values": "registry_exact_artifact_hash_lookup",
    }

    return methods.get(field, "registry_lookup")


def field_decision_base(candidate, evidence, field, old_value, eligibility_class):
    ecosystem = clean(candidate.get("ecosystem_normalized")) or clean(
        candidate.get("ecosystem")
    )

    return {
        "component_id": clean(candidate.get("component_id")),
        "project_id": clean(candidate.get("project_id")),
        "ecosystem": ecosystem,
        "tool": clean(candidate.get("tool")),
        "sbom_path": clean(candidate.get("sbom_path")),
        "component_index": clean(candidate.get("component_index")),
        "name": clean(candidate.get("name")),
        "version": clean(candidate.get("version")),
        "purl": clean(candidate.get("purl")),
        "field_name": field,
        "old_value": old_value,
        "eligibility_class": eligibility_class,
        "target_fields_predicted": clean(candidate.get("target_fields_predicted")),
        "manual_review_fields_predicted": clean(
            candidate.get("manual_review_fields_predicted")
        ),
        "excluded_fields_predicted": clean(candidate.get("excluded_fields_predicted")),
        "repair_decision_predicted": clean(
            candidate.get("repair_decision_predicted")
        ),
        "matched_rule_ids": clean(candidate.get("matched_rule_ids")),
        "manual_review_reason": clean(candidate.get("manual_review_reason")),
        "evidence_status": clean(evidence.get("evidence_status")) if evidence else "",
        "evidence_source": clean(evidence.get("evidence_source")) if evidence else "",
        "evidence_confidence": clean(evidence.get("evidence_confidence")) if evidence else "",
        "evidence_exact_version_match": clean(
            evidence.get("evidence_exact_version_match")
        )
        if evidence
        else "",
        "field_repair_status": "",
        "field_status_reason": "",
        "new_value": "",
        "evidence_reference": "",
        "repair_method": "",
        "evidence_party_role": clean(evidence.get("evidence_party_role"))
        if evidence
        else "",
        "evidence_party_source_field": clean(
            evidence.get("evidence_party_source_field")
        )
        if evidence
        else "",
        "evidence_artifact_match": clean(evidence.get("evidence_artifact_match"))
        if evidence
        else "",
        "evidence_artifact_match_method": clean(
            evidence.get("evidence_artifact_match_method")
        )
        if evidence
        else "",
        "evidence_hash_usable_for_auto_repair": clean(
            evidence.get("evidence_hash_usable_for_auto_repair")
        )
        if evidence
        else "",
    }


def main():
    candidates, candidate_fields = load_csv(CANDIDATES_FILE)
    evidence_rows, _evidence_fields = load_csv(EVIDENCE_FILE)

    evidence_index = build_evidence_index(evidence_rows)
    repaired_at = now_utc()

    repair_plan_rows = []
    provenance_rows = []
    field_decision_rows = []
    enriched_rows = []

    field_counter = Counter()
    ecosystem_field_counter = Counter()
    field_status_counter = Counter()
    field_status_by_field_counter = Counter()

    for candidate in candidates:
        enriched = dict(candidate)
        key = candidate_key(candidate)
        evidence = evidence_index.get(key)

        auto_targets = parse_field_spec(candidate.get("target_fields_predicted"))
        manual_spec = clean(candidate.get("manual_review_fields_predicted"))
        excluded_spec = clean(candidate.get("excluded_fields_predicted"))

        component_repairs = []
        component_manual_fields = []
        component_excluded_fields = []
        component_unresolved_auto_fields = []
        component_not_targeted_fields = []
        component_eligibility_conflicts = []

        for field in REPAIRABLE_FIELDS:
            old_value = clean(candidate.get(field))

            # Field-level decisions concern missing metadata only.
            if is_present(old_value):
                continue

            auto_target = field in auto_targets
            manual_target = field_marked(field, manual_spec)
            excluded_target = field_marked(field, excluded_spec)

            # Safety precedence: explicit exclusion/manual-review overrides
            # an accidental simultaneous automatic target.
            eligibility_conflict = auto_target and (manual_target or excluded_target)

            if excluded_target:
                eligibility_class = "excluded"
            elif manual_target:
                eligibility_class = "manual_review"
            elif auto_target:
                eligibility_class = "automatic_target"
            else:
                eligibility_class = "not_targeted"

            decision = field_decision_base(
                candidate, evidence, field, old_value, eligibility_class
            )

            if eligibility_conflict:
                component_eligibility_conflicts.append(field)
                decision["field_repair_status"] = "manual_review_required"
                decision["field_status_reason"] = "eligibility_conflict_abstention_precedence"
                component_manual_fields.append(field)
                field_decision_rows.append(decision)
                field_status_counter[decision["field_repair_status"]] += 1
                field_status_by_field_counter[(field, decision["field_repair_status"])] += 1
                continue

            if excluded_target:
                decision["field_repair_status"] = "excluded"
                decision["field_status_reason"] = (
                    clean(candidate.get("exclusion_reason")) or "field_excluded_by_classifier"
                )
                component_excluded_fields.append(field)

            elif manual_target:
                decision["field_repair_status"] = "manual_review_required"
                decision["field_status_reason"] = (
                    clean(candidate.get("manual_review_reason"))
                    or "field_marked_for_manual_review"
                )
                component_manual_fields.append(field)

            elif not auto_target:
                decision["field_repair_status"] = "not_targeted"
                decision["field_status_reason"] = "no_automatic_repair_rule_for_field"
                component_not_targeted_fields.append(field)

            else:
                base_ok, base_reason = base_evidence_acceptable(evidence)

                if not base_ok:
                    decision["field_repair_status"] = "automatic_target_not_proposed"
                    decision["field_status_reason"] = base_reason
                    component_unresolved_auto_fields.append(field)
                else:
                    field_ok, field_reason = field_evidence_allowed(
                        candidate, evidence, field
                    )

                    if not field_ok:
                        decision["field_repair_status"] = "automatic_target_not_proposed"
                        decision["field_status_reason"] = field_reason
                        component_unresolved_auto_fields.append(field)
                    else:
                        raw_new_value = evidence_value_for_field(evidence, field)

                        if is_missing(raw_new_value):
                            decision["field_repair_status"] = "automatic_target_not_proposed"
                            decision["field_status_reason"] = "retrieved_field_value_missing"
                            component_unresolved_auto_fields.append(field)
                        else:
                            new_value = normalize_field_value(field, raw_new_value)

                            if is_missing(new_value):
                                decision["field_repair_status"] = "automatic_target_not_proposed"
                                decision["field_status_reason"] = (
                                    "field_value_empty_after_normalization"
                                )
                                component_unresolved_auto_fields.append(field)
                            else:
                                source = evidence_source_for_field(evidence, field)
                                reference = evidence_reference_for_field(evidence, field)
                                method = repair_method_for_field(field)
                                confidence = clean(evidence.get("evidence_confidence"))

                                repair = {
                                    "field_name": field,
                                    "old_value": old_value,
                                    "new_value": new_value,
                                    "evidence_source": source,
                                    "evidence_reference": reference,
                                    "repair_method": method,
                                    "confidence": confidence,
                                }
                                component_repairs.append(repair)
                                enriched[field] = new_value

                                decision["field_repair_status"] = "repair_proposed"
                                decision["field_status_reason"] = field_reason
                                decision["new_value"] = new_value
                                decision["evidence_reference"] = reference
                                decision["repair_method"] = method

            field_decision_rows.append(decision)
            field_status_counter[decision["field_repair_status"]] += 1
            field_status_by_field_counter[(field, decision["field_repair_status"])] += 1

        original_decision = clean(candidate.get("repair_decision_predicted"))

        if component_repairs:
            repair_status = "repair_proposed"
        elif auto_targets:
            if not evidence:
                repair_status = "no_evidence_available"
            else:
                base_ok, _ = base_evidence_acceptable(evidence)
                if not base_ok:
                    repair_status = "evidence_not_acceptable"
                else:
                    repair_status = "no_missing_repairable_field_with_evidence"
        else:
            repair_status = "not_auto_repair_candidate"

        repair_fields = ";".join(r["field_name"] for r in component_repairs)
        manual_fields = ";".join(sorted(set(component_manual_fields)))
        excluded_fields = ";".join(sorted(set(component_excluded_fields)))
        unresolved_auto_fields = ";".join(sorted(set(component_unresolved_auto_fields)))
        not_targeted_fields = ";".join(sorted(set(component_not_targeted_fields)))
        conflict_fields = ";".join(sorted(set(component_eligibility_conflicts)))

        enriched["repair_status"] = repair_status
        enriched["repair_fields"] = repair_fields
        enriched["field_manual_review_fields"] = manual_fields
        enriched["field_excluded_fields"] = excluded_fields
        enriched["field_unresolved_auto_fields"] = unresolved_auto_fields
        enriched["field_not_targeted_fields"] = not_targeted_fields
        enriched["field_eligibility_conflicts"] = conflict_fields
        enriched["repaired_at"] = repaired_at if component_repairs else ""
        enriched_rows.append(enriched)

        ecosystem = clean(candidate.get("ecosystem_normalized")) or clean(
            candidate.get("ecosystem")
        )

        repair_plan_rows.append(
            {
                "component_id": clean(candidate.get("component_id")),
                "project_id": clean(candidate.get("project_id")),
                "ecosystem": ecosystem,
                "tool": clean(candidate.get("tool")),
                "sbom_path": clean(candidate.get("sbom_path")),
                "component_index": clean(candidate.get("component_index")),
                "name": clean(candidate.get("name")),
                "version": clean(candidate.get("version")),
                "purl": clean(candidate.get("purl")),
                "repair_decision_predicted": original_decision,
                "target_fields_predicted": clean(
                    candidate.get("target_fields_predicted")
                ),
                "manual_review_fields_predicted": manual_spec,
                "excluded_fields_predicted": excluded_spec,
                "repair_status": repair_status,
                "repair_fields": repair_fields,
                "repair_count": len(component_repairs),
                "field_manual_review_fields": manual_fields,
                "field_manual_review_count": len(set(component_manual_fields)),
                "field_excluded_fields": excluded_fields,
                "field_excluded_count": len(set(component_excluded_fields)),
                "field_unresolved_auto_fields": unresolved_auto_fields,
                "field_unresolved_auto_count": len(set(component_unresolved_auto_fields)),
                "field_not_targeted_fields": not_targeted_fields,
                "field_eligibility_conflicts": conflict_fields,
                "has_field_specific_abstention": bool_text(
                    bool(component_manual_fields)
                ),
                "evidence_status": clean(evidence.get("evidence_status"))
                if evidence
                else "",
                "evidence_source": clean(evidence.get("evidence_source"))
                if evidence
                else "",
                "evidence_confidence": clean(evidence.get("evidence_confidence"))
                if evidence
                else "",
                "evidence_exact_version_match": clean(
                    evidence.get("evidence_exact_version_match")
                )
                if evidence
                else "",
            }
        )

        for repair in component_repairs:
            field_counter[repair["field_name"]] += 1
            ecosystem_field_counter[(ecosystem, repair["field_name"])] += 1

            provenance_rows.append(
                {
                    "component_id": clean(candidate.get("component_id")),
                    "project_id": clean(candidate.get("project_id")),
                    "ecosystem": ecosystem,
                    "tool": clean(candidate.get("tool")),
                    "sbom_path": clean(candidate.get("sbom_path")),
                    "component_index": clean(candidate.get("component_index")),
                    "name": clean(candidate.get("name")),
                    "version": clean(candidate.get("version")),
                    "purl": clean(candidate.get("purl")),
                    "field_name": repair["field_name"],
                    "old_value": repair["old_value"],
                    "new_value": repair["new_value"],
                    "evidence_source": repair["evidence_source"],
                    "evidence_reference": repair["evidence_reference"],
                    "repair_method": repair["repair_method"],
                    "confidence": repair["confidence"],
                    "evidence_party_role": clean(evidence.get("evidence_party_role"))
                    if evidence
                    else "",
                    "evidence_party_source_field": clean(
                        evidence.get("evidence_party_source_field")
                    )
                    if evidence
                    else "",
                    "evidence_artifact_match": clean(
                        evidence.get("evidence_artifact_match")
                    )
                    if evidence
                    else "",
                    "evidence_artifact_match_method": clean(
                        evidence.get("evidence_artifact_match_method")
                    )
                    if evidence
                    else "",
                    "repaired_at": repaired_at,
                }
            )

    write_csv(REPAIR_PLAN_FILE, repair_plan_rows)
    write_csv(PROVENANCE_FILE, provenance_rows)
    write_csv(FIELD_DECISIONS_FILE, field_decision_rows)

    enriched_fields = list(candidate_fields)
    for field in [
        "repair_status",
        "repair_fields",
        "field_manual_review_fields",
        "field_excluded_fields",
        "field_unresolved_auto_fields",
        "field_not_targeted_fields",
        "field_eligibility_conflicts",
        "repaired_at",
    ]:
        if field not in enriched_fields:
            enriched_fields.append(field)

    write_csv(ENRICHED_PREVIEW_FILE, enriched_rows, enriched_fields)

    write_summary(repair_plan_rows, provenance_rows, field_decision_rows)
    write_summary_by_field(field_counter)
    write_summary_by_ecosystem(ecosystem_field_counter)
    write_field_decision_summary(field_status_by_field_counter)

    print(f"Saved repair plan to: {REPAIR_PLAN_FILE}")
    print(f"Saved provenance to: {PROVENANCE_FILE}")
    print(f"Saved field decisions to: {FIELD_DECISIONS_FILE}")
    print(f"Saved enriched preview to: {ENRICHED_PREVIEW_FILE}")
    print(f"Saved summary to: {SUMMARY_FILE}")
    print(f"Saved field summary to: {SUMMARY_BY_FIELD_FILE}")
    print(f"Saved ecosystem summary to: {SUMMARY_BY_ECOSYSTEM_FILE}")
    print(f"Saved field-decision summary to: {FIELD_DECISION_SUMMARY_FILE}")

    print("\nProposed repairs by field:")
    for field, count in field_counter.most_common():
        print(f"{field}: {count}")

    print("\nField-level decision summary:")
    for status, count in field_status_counter.most_common():
        print(f"{status}: {count}")


def write_summary(repair_plan_rows, provenance_rows, field_decision_rows):
    total_components = len(repair_plan_rows)
    components_with_repairs = sum(
        1 for row in repair_plan_rows if row["repair_status"] == "repair_proposed"
    )
    components_with_field_abstention = sum(
        1
        for row in repair_plan_rows
        if lower(row.get("has_field_specific_abstention")) == "true"
    )
    total_field_repairs = len(provenance_rows)
    total_missing_field_decisions = len(field_decision_rows)
    total_manual_review_fields = sum(
        1
        for row in field_decision_rows
        if row.get("field_repair_status") == "manual_review_required"
    )

    status_counts = Counter(row["repair_status"] for row in repair_plan_rows)

    rows = [
        {
            "metric": "total_components",
            "value": total_components,
            "percentage": "100.00",
        },
        {
            "metric": "components_with_repairs",
            "value": components_with_repairs,
            "percentage": (
                f"{components_with_repairs / total_components * 100:.2f}"
                if total_components
                else "0.00"
            ),
        },
        {
            "metric": "components_with_field_specific_abstention",
            "value": components_with_field_abstention,
            "percentage": (
                f"{components_with_field_abstention / total_components * 100:.2f}"
                if total_components
                else "0.00"
            ),
        },
        {
            "metric": "total_field_repairs",
            "value": total_field_repairs,
            "percentage": "",
        },
        {
            "metric": "total_missing_field_decisions",
            "value": total_missing_field_decisions,
            "percentage": "100.00" if total_missing_field_decisions else "0.00",
        },
        {
            "metric": "manual_review_field_decisions",
            "value": total_manual_review_fields,
            "percentage": (
                f"{total_manual_review_fields / total_missing_field_decisions * 100:.2f}"
                if total_missing_field_decisions
                else "0.00"
            ),
        },
    ]

    for status, count in status_counts.most_common():
        rows.append(
            {
                "metric": f"repair_status:{status}",
                "value": count,
                "percentage": (
                    f"{count / total_components * 100:.2f}"
                    if total_components
                    else "0.00"
                ),
            }
        )

    write_csv(SUMMARY_FILE, rows, ["metric", "value", "percentage"])


def write_summary_by_field(field_counter):
    total_repairs = sum(field_counter.values())
    rows = []

    for field, count in field_counter.most_common():
        rows.append(
            {
                "field_name": field,
                "repair_count": count,
                "percentage_of_repairs": (
                    f"{count / total_repairs * 100:.2f}" if total_repairs else "0.00"
                ),
            }
        )

    write_csv(
        SUMMARY_BY_FIELD_FILE,
        rows,
        ["field_name", "repair_count", "percentage_of_repairs"],
    )


def write_summary_by_ecosystem(ecosystem_field_counter):
    rows = []
    ecosystem_totals = defaultdict(int)

    for (ecosystem, field), count in ecosystem_field_counter.items():
        ecosystem_totals[ecosystem] += count

    for (ecosystem, field), count in sorted(ecosystem_field_counter.items()):
        total = ecosystem_totals[ecosystem]
        rows.append(
            {
                "ecosystem": ecosystem,
                "field_name": field,
                "repair_count": count,
                "percentage_within_ecosystem": (
                    f"{count / total * 100:.2f}" if total else "0.00"
                ),
            }
        )

    write_csv(
        SUMMARY_BY_ECOSYSTEM_FILE,
        rows,
        [
            "ecosystem",
            "field_name",
            "repair_count",
            "percentage_within_ecosystem",
        ],
    )


def write_field_decision_summary(field_status_by_field_counter):
    rows = []

    field_totals = Counter()
    for (field, status), count in field_status_by_field_counter.items():
        field_totals[field] += count

    for (field, status), count in sorted(field_status_by_field_counter.items()):
        total = field_totals[field]
        rows.append(
            {
                "field_name": field,
                "field_repair_status": status,
                "count": count,
                "percentage_within_field": (
                    f"{count / total * 100:.2f}" if total else "0.00"
                ),
            }
        )

    write_csv(
        FIELD_DECISION_SUMMARY_FILE,
        rows,
        [
            "field_name",
            "field_repair_status",
            "count",
            "percentage_within_field",
        ],
    )


if __name__ == "__main__":
    main()
