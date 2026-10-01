
## 1. Purpose

This phase defines the first version of the repair decision logic for SHM, the Semantic Harmonization Agent.

The purpose is to decide, for each SBOM component:

1. whether the component should be repaired automatically,
2. which metadata fields are eligible for repair,
3. which evidence source should be used,
4. when the component should be excluded from public-registry repair,
5. when manual review is required,
6. what confidence level should be assigned to each repair decision, and
7. what provenance evidence must be recorded.

This phase is based on:

- raw SBOM missing-field statistics,
- metadata completeness scoring,
- Phase 13 pilot manual inspection,
- Phase 13 targeted defect inspection,
- observed component roles such as external dependency, internal module, local fixture, workflow component, and root project component.

---

## 2. Motivation

Manual inspection showed that not all SBOM components are normal public package dependencies.

The inspected components included:

- external npm dependencies,
- external PyPI dependencies,
- external Maven dependencies,
- internal repository modules,
- local fixtures or test artifacts,
- generated local jars,
- GitHub Actions workflow components,
- root project components,
- duplicate-looking components,
- components with missing identity fields,
- components with placeholder values such as `latest`,
- components where distribution URLs were present but repository URLs were absent.

Therefore, SHM should not blindly enrich every component using npm, PyPI, or Maven Central.

Instead, SHM first applies a repair eligibility decision.

---

## 3. Key Principle

SHM should only perform automatic public-registry repair when the component is a clear external dependency with sufficient identity evidence.

For internal modules, local test fixtures, root project components, workflow components, or ambiguous identities, SHM should either exclude the component from registry repair or route it to manual review.

The guiding principle is:

```text
Do not increase completeness at the cost of correctness.

A missing field should remain missing if the available evidence is not strong enough to repair it safely.
```

---

## 4. Terminology

### 4.1 Component

A component is one software item listed in an SBOM. It may be an external dependency, internal module, root project, workflow action, local fixture, generated artifact, or build-related component.

### 4.2 Registry repair

Registry repair means enriching SBOM metadata using public package registries such as:

- npm registry,
- PyPI,
- Maven Central.

Registry repair is suitable for public package dependencies, but not necessarily for internal modules, local artifacts, root project components, or workflow components.

### 4.3 Evidence-aware repair

Evidence-aware repair means every enriched field must be supported by a recorded evidence source.

Examples of evidence include:

- registry metadata,
- package manifest,
- POM file,
- package-lock file,
- GitHub repository metadata,
- SPDX license list,
- existing SBOM component JSON,
- workflow file evidence.

### 4.4 Confidence

Confidence expresses how safe the repair decision is, based on the strength of the available evidence.

Confidence values used in this study:

- high
- medium
- low
- none

These are qualitative confidence categories, not probabilistic scores.

---

## 5. Repair Decision Categories

| Repair decision | Meaning |
|---|---|
| `auto_repair_candidate` | SHM may automatically enrich the component using trusted evidence sources. |
| `manual_review_required` | SHM should not automatically repair the component without additional human or evidence-based confirmation. |
| `exclude_from_registry_repair` | SHM should not use npm, PyPI, or Maven Central to repair this component. |
| `no_repair_needed` | The relevant fields are already sufficiently present or no repair is necessary. |

---

## 6. Component Role Categories

| Component role | Meaning | Registry repair? |
|---|---|---|
| `external_dependency` | A third-party package/library from npm, PyPI, Maven, or similar package ecosystem | Usually yes |
| `internal_module` | A module or submodule belonging to the analyzed repository | No |
| `local_fixture_or_test_artifact` | A local test/demo/sample/generated artifact | No |
| `workflow_component` | A GitHub Action or CI/CD workflow component | No for npm/PyPI/Maven repair |
| `root_project` | The main project for which the SBOM was generated | Usually manual/project metadata repair |
| `build_plugin_or_tool` | Build plugin, build tool, documentation tool, compiler plugin | Depends on ecosystem and identity |
| `unknown` | Component role cannot be determined confidently | Manual review |

---

## 7. Evidence Sources

| Evidence source | Used for |
|---|---|
| `npm_registry` | npm package license, repository URL, distribution URL, maintainers, integrity/hash when available |
| `pypi_registry` | PyPI package metadata, project URLs, license, distribution files |
| `maven_central` | Maven coordinates, POM metadata, licenses, developers/organization, artifact hashes |
| `pom_xml` | Maven project metadata, dependency coordinates, licenses, organization, developers |
| `package_lock` | npm package identity, version, resolved distribution artifacts, integrity values |
| `github_repository` | Repository URL, project metadata, root project information, GitHub Actions metadata |
| `workflow_file` | GitHub Actions usage evidence |
| `spdx_license_list` | License normalization and validation |
| `sbom_internal_evidence` | Existing SBOM fields, external references, properties, and raw component JSON |
| `local_project_evidence` | Local manifests, local jars, build files, project modules |
| `manual_review` | Human decision for ambiguous or risky cases |

---

## 8. Field Repair Priorities

| Field | Priority | Reason |
|---|---|---|
| `repository_url` | Very high | Missing almost everywhere and useful for provenance analysis |
| `supplier` | Very high | Missing almost everywhere and useful for supply-chain attribution |
| `license` | High | Often missing and important for compliance |
| `purl` | Medium | Mostly present, but missing or malformed in some cases |
| `distribution_url` | Medium | Useful for artifact traceability but ecosystem-dependent |
| `hash_values` | Medium/Low initially | Requires exact artifact evidence |
| `version` | Careful/manual | Incorrect version repair can cause false matches |
| `name` | Usually not repaired | Core identity field; changing it risks corrupting identity |

---

## 9. General Confidence Policy

| Situation | Confidence |
|---|---|
| Exact package and version match from npm registry | high |
| Exact package and version match from PyPI registry | high |
| Exact Maven group/artifact/version match from Maven Central | high |
| Existing SPDX license identifier or valid SPDX expression | high |
| Repository URL found directly in registry metadata | high or medium depending on source clarity |
| Supplier inferred from package organization, owner, or maintainer metadata | medium |
| PURL generated from clear ecosystem + name + version | medium |
| Distribution URL found from exact package/version metadata | high |
| Hash found for exact downloadable artifact | high |
| Missing version | low |
| Placeholder version such as `latest` | low |
| Ambiguous package name | low |
| Internal/local/workflow component for package-registry repair | none |
| Component excluded from registry repair | none |
| Manual-review-only decision | low or medium, depending on available evidence |

Confidence is assigned to the repair decision and to each repaired field. If evidence is weak, SHM should not automatically repair the field.

---

## 10. Core Repair Rules

### Rule R1: Clear external npm dependency

**Condition**

```
component_role = external_dependency
AND ecosystem = npm
AND identity_status = clear_identity
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- license_lookup
- repository_lookup
- supplier_lookup
- distribution_url_lookup

**Target fields**

- license
- repository_url
- supplier
- distribution_url

**Evidence sources**

- npm_registry
- spdx_license_list

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| npm package name and version match exactly | high |
| purl exists and matches npm package/version | high |
| license from npm metadata is SPDX-compatible | high |
| repository URL found in npm metadata repository field | high |
| supplier inferred from npm scope or package owner/maintainer | medium |
| package exists but requested version is not found | low |
| package name exists but identity is ambiguous | low |

**Provenance required?**

yes

**Notes**

npm packages with clear purl/name/version are safe candidates for registry-based enrichment.

---

### Rule R2: Clear external PyPI dependency

**Condition**

```
component_role = external_dependency
AND ecosystem = pypi
AND identity_status = clear_identity
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- license_lookup
- repository_lookup
- supplier_lookup
- distribution_url_lookup

**Target fields**

- license
- repository_url
- supplier
- distribution_url

**Evidence sources**

- pypi_registry
- spdx_license_list

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| PyPI package name and version match exactly | high |
| purl exists and matches PyPI package/version | high |
| license appears in PyPI license field or classifiers | medium to high |
| license classifier maps clearly to SPDX | high |
| repository URL appears in PyPI project URLs | high |
| supplier inferred from author/maintainer metadata | medium |
| package exists but requested version is not found | low |
| package name exists but metadata is incomplete or inconsistent | medium |
| package name is ambiguous or normalized differently | low |

**Provenance required?**

yes

**Notes**

PyPI packages with clear identity are safe candidates for registry-based enrichment, but license fields may require normalization because PyPI metadata can contain free text or classifiers.

---

### Rule R3: Clear external Maven dependency

**Condition**

```
component_role = external_dependency
AND ecosystem = maven
AND identity_status = clear_identity
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- license_lookup
- repository_lookup
- supplier_lookup
- distribution_url_lookup
- hash_lookup

**Target fields**

- license
- repository_url
- supplier
- distribution_url
- hash_values

**Evidence sources**

- maven_central
- pom_xml
- spdx_license_list

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| Maven group/artifact/version match exactly | high |
| POM file for exact GAV is available | high |
| license appears in exact artifact POM | high |
| project URL or SCM URL appears in exact artifact POM | high |
| organization/developer metadata appears in exact artifact POM | medium |
| artifact checksum is available for exact version | high |
| group and artifact match but version is missing | low |
| artifact name matches but group is missing | low |
| multiple candidate artifacts exist | low |

**Provenance required?**

yes

**Notes**

Maven components require exact group, artifact, and version matching before enrichment. Maven hash repair is safer than npm/PyPI hash repair when exact artifact coordinates are available.

---

### Rule R4: Missing purl but clear identity

**Condition**

```
component_role = external_dependency
AND purl_status = missing
AND name_present = yes
AND version_status = present
AND ecosystem_known = yes
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- purl_generation

**Target fields**

- purl

**Evidence sources**

- ecosystem_purl_rules
- sbom_internal_evidence

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| ecosystem, name, and version are all present | medium |
| Maven group, artifact, and version are all present | high |
| npm scoped package name is clear | medium to high |
| PyPI normalized package name is clear | medium |
| ecosystem is inferred but not explicitly known | low |
| namespace/group is missing for Maven | low |
| version is missing or placeholder | low |

**Provenance required?**

yes

**Manual review trigger**

Manual review is required if ecosystem, group, namespace, or version is unclear.

**Notes**

PURL generation is allowed only when ecosystem identity is sufficiently clear. SHM should not invent purls for ambiguous components.

---

### Rule R5: Malformed or placeholder purl

**Condition**

```
purl_status = malformed
OR purl_status = placeholder_version
```

**Repair decision**

`manual_review_required`

**Repair actions**

- purl_correction
- manual_review

**Target fields**

- purl

**Evidence sources**

- manifest
- package_registry
- manual_review

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| purl has valid ecosystem but placeholder version such as `latest` | low |
| purl has missing Maven group/artifact structure | low |
| purl ecosystem conflicts with component evidence | low |
| manifest confirms exact package coordinates | medium |
| registry confirms exact identity after correction | medium to high |
| correction cannot be supported by evidence | low or no repair |

**Provenance required?**

yes

**Notes**

Malformed or placeholder purls should not be automatically corrected unless supported by strong evidence.

---

### Rule R6: Missing or placeholder version

**Condition**

```
version_status = missing
OR version_status = placeholder
```

**Repair decision**

`manual_review_required`

**Repair actions**

- version_lookup
- manual_review

**Target fields**

- version
- purl

**Evidence sources**

- manifest
- repository_metadata
- manual_review

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| exact version found in local manifest | high |
| exact version found in lockfile | high |
| root project version found in project manifest | medium to high |
| version inferred from release tag only | medium |
| version inferred from latest registry release | low |
| version missing and multiple candidates exist | low |
| placeholder value such as `latest` | low |

**Provenance required?**

yes

**Notes**

Missing or placeholder versions reduce confidence and may cause false registry matches. SHM should avoid automatic repair unless exact version evidence is available.

---

### Rule R7: Internal module

**Condition**

```
component_role = internal_module
```

**Repair decision**

`exclude_from_registry_repair`

**Repair actions**

- exclude_internal_component

**Target fields**

- none

**Evidence sources**

- local_project_evidence
- manual_review

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| component path points inside repository module | high for exclusion |
| group/name matches project-internal namespace | high for exclusion |
| component appears in local build output only | medium to high for exclusion |
| component could also be a public package | medium; manual review recommended |
| no local evidence exists | low; manual review required |

**Provenance required?**

yes

**Notes**

Internal modules should not be enriched using public package registries because a registry lookup may return an unrelated public package.

---

### Rule R8: Local fixture or test artifact

**Condition**

```
component_role = local_fixture_or_test_artifact
```

**Repair decision**

`exclude_from_registry_repair`

**Repair actions**

- exclude_internal_component

**Target fields**

- none

**Evidence sources**

- local_project_evidence
- manual_review

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| component path contains test, sample, fixture, demo, or integration-test evidence | high for exclusion |
| artifact name indicates sample/demo/local jar | medium to high for exclusion |
| group is `com.example` or similar test namespace | high for exclusion |
| component has local jar evidence only | high for exclusion |
| artifact also appears in a public registry | medium; manual review recommended |

**Provenance required?**

yes

**Notes**

Local fixtures and generated test artifacts may not exist in public registries. They should not be repaired through public package registries.

---

### Rule R9: Workflow component

**Condition**

```
component_role = workflow_component
```

**Repair decision**

`exclude_from_registry_repair`

**Repair actions**

- exclude_workflow_component

**Target fields**

- none

**Evidence sources**

- github_repository
- workflow_file
- manual_review

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| purl type is `pkg:github/...` | high for workflow classification |
| properties indicate github-action | high for workflow classification |
| component found in `.github/workflows` | high for workflow classification |
| component name follows owner/action format | medium to high |
| workflow component lacks pinned version | medium; manual review for versioning |
| component could also be a package dependency | medium; manual review recommended |

**Provenance required?**

yes

**Notes**

GitHub Actions should not be repaired using npm, PyPI, or Maven Central. They may be enriched using GitHub repository or workflow evidence in a later SHM extension.

---

### Rule R10: Root project component

**Condition**

```
component_role = root_project
```

**Repair decision**

`manual_review_required`

**Repair actions**

- project_metadata_lookup
- manual_review

**Target fields**

- version
- license
- repository_url
- supplier

**Evidence sources**

- github_repository
- manifest
- manual_review

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| root project metadata appears in repository manifest | high |
| license appears in repository root LICENSE file or manifest | medium to high |
| repository URL is known from dataset source | high |
| version appears in project manifest | medium to high |
| version is placeholder such as `latest` | low |
| root project identity conflicts with dependency identity | low |

**Provenance required?**

yes

**Notes**

Root project metadata should come from repository and project manifests rather than dependency registries.

---

### Rule R11: License expression present

**Condition**

```
license_presence_status = present_in_expression
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- license_normalization

**Target fields**

- license

**Evidence sources**

- sbom_internal_evidence
- spdx_license_list

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| expression is valid SPDX expression | high |
| expression contains valid SPDX identifiers with operators | high |
| expression has minor formatting issue but normalizes unambiguously | medium |
| expression contains non-SPDX free text | low |
| expression contains unknown license terms | low; manual review required |

**Provenance required?**

yes

**Notes**

License expressions are not missing. SHM should parse and normalize them before attempting registry lookup.

---

### Rule R12: License absent for clear external dependency

**Condition**

```
component_role = external_dependency
AND identity_status = clear_identity
AND license_presence_status = absent
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- license_lookup
- license_normalization

**Target fields**

- license

**Evidence sources**

- package_registry
- spdx_license_list

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| exact package/version registry metadata provides SPDX license | high |
| exact package/version registry metadata provides license classifier mapping to SPDX | high |
| registry provides free-text license that maps unambiguously to SPDX | medium |
| registry provides conflicting license fields | low; manual review required |
| package-level license exists but version-specific license is absent | medium |
| license not found in registry | no repair |

**Provenance required?**

yes

**Notes**

License lookup should be evidence-based and normalized against SPDX when possible.

---

### Rule R13: Repository URL absent for clear external dependency

**Condition**

```
component_role = external_dependency
AND identity_status = clear_identity
AND repository_url_status = absent
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- repository_lookup

**Target fields**

- repository_url

**Evidence sources**

- package_registry
- github_repository

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| registry metadata has explicit repository/source/scm URL | high |
| Maven POM has SCM connection or developerConnection URL | high |
| PyPI project URLs contain Source/Repository/Homepage clearly pointing to source repo | medium to high |
| npm repository field points to GitHub/GitLab/etc. | high |
| only homepage is available and may not be source repository | medium |
| only distribution URL is available | no repository repair |
| multiple repository candidates exist | low; manual review required |

**Provenance required?**

yes

**Notes**

Distribution URLs must not be copied into repository_url.

---

### Rule R14: Distribution URL present but repository URL absent

**Condition**

```
distribution_url_status = present
AND repository_url_status = absent
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- repository_lookup

**Target fields**

- repository_url

**Evidence sources**

- package_registry
- github_repository

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| distribution URL confirms exact package/version identity | medium |
| registry lookup using that identity returns repository URL | high |
| distribution URL is the only available URL | no repository repair |
| distribution URL is incorrectly treated as source URL | invalid repair |
| repository URL requires inference from package name only | low |

**Provenance required?**

yes

**Notes**

A distribution URL is useful evidence for artifact identity, but it is not the same as a repository URL.

---

### Rule R15: Supplier absent for clear external dependency

**Condition**

```
component_role = external_dependency
AND identity_status = clear_identity
AND supplier_missing = yes
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- supplier_lookup

**Target fields**

- supplier

**Evidence sources**

- package_registry
- project_metadata

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| registry provides explicit organization or publisher | high |
| Maven POM provides organization name | high |
| supplier inferred from npm scope | medium |
| supplier inferred from maintainer/author field | medium |
| supplier inferred from GitHub owner | medium |
| multiple maintainers exist with no organization | low |
| no reliable supplier metadata exists | no repair |

**Provenance required?**

yes

**Notes**

Supplier is difficult because ecosystems differ in how they represent authors, maintainers, publishers, and organizations. SHM should record exactly how supplier was inferred.

---

### Rule R16: Hash absent for Maven exact artifact

**Condition**

```
component_role = external_dependency
AND ecosystem = maven
AND identity_status = clear_identity
AND hash_status = absent
```

**Repair decision**

`auto_repair_candidate`

**Repair actions**

- hash_lookup

**Target fields**

- hash_values

**Evidence sources**

- maven_central

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| exact Maven GAV artifact checksum is available | high |
| checksum corresponds to exact jar/pom artifact | high |
| only group/artifact exists but version missing | low |
| multiple classifiers/artifact files exist | medium; artifact type must be specified |
| checksum belongs to different artifact packaging | invalid repair |

**Provenance required?**

yes

**Notes**

Hash repair is safer for Maven when exact artifact coordinates are available.

---

### Rule R17: Hash absent for npm or PyPI

**Condition**

```
component_role = external_dependency
AND ecosystem IN npm,pypi
AND hash_status = absent
```

**Repair decision**

`manual_review_required`

**Repair actions**

- hash_lookup
- manual_review

**Target fields**

- hash_values

**Evidence sources**

- npm_registry
- pypi_registry

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| exact distribution artifact URL is known | medium to high |
| lockfile integrity value is available | high |
| registry provides integrity/checksum for exact version artifact | high |
| multiple distribution files exist for same version | medium; file selection required |
| no exact artifact URL exists | low |
| hash would be inferred from package-level metadata only | invalid repair |

**Provenance required?**

yes

**Notes**

Hash lookup requires exact artifact or distribution file match. SHM v1 may defer npm/PyPI hash repair unless artifact evidence is strong.

---

### Rule R18: Duplicate same purl

**Condition**

```
duplicate_status = duplicate_same_purl
```

**Repair decision**

`manual_review_required`

**Repair actions**

- duplicate_resolution

**Target fields**

- none

**Evidence sources**

- sbom_internal_evidence

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| exact purl appears multiple times with identical metadata | medium |
| exact purl appears multiple times from different dependency paths | medium; may be legitimate |
| exact purl appears multiple times with conflicting metadata | low; manual review required |
| duplicate caused by tool behavior | medium |
| duplicate caused by transitive dependency structure | not necessarily an error |

**Provenance required?**

yes

**Notes**

A duplicate may reflect dependency tree repetition or SBOM generator behavior. It should not automatically be treated as an error.

---

### Rule R19: Duplicate same name different version

**Condition**

```
duplicate_status = duplicate_name_different_version
```

**Repair decision**

`manual_review_required`

**Repair actions**

- duplicate_analysis

**Target fields**

- none

**Evidence sources**

- sbom_internal_evidence

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| same name appears with different versions in npm dependency tree | medium; often legitimate |
| same Maven artifact appears with different versions | medium; may reflect dependency conflicts or modules |
| same name appears with different ecosystems | low; identity ambiguity possible |
| same name/version appears with conflicting purls | low; manual review required |
| deduplication policy is explicitly defined | confidence depends on policy |

**Provenance required?**

yes

**Notes**

Multiple versions may be legitimate in transitive dependency trees. SHM should not collapse these automatically without a deduplication policy.

---

### Rule R20: Ambiguous identity

**Condition**

```
identity_status = ambiguous_identity
OR identity_status = missing_identity
```

**Repair decision**

`manual_review_required`

**Repair actions**

- manual_review

**Target fields**

- none

**Evidence sources**

- manual_review
- manifest
- repository_metadata

**Confidence policy**

| Evidence condition | Confidence |
|---|---|
| package name exists in multiple ecosystems | low |
| package name exists under multiple namespaces/groups | low |
| version is missing and name is generic | low |
| component lacks purl and group/namespace | low |
| local manifest resolves identity clearly | medium to high |
| registry search returns multiple plausible candidates | low; manual review required |

**Provenance required?**

yes

**Notes**

Do not automatically repair components whose package identity is unclear. Ambiguous or missing identities should be routed to manual review unless local manifest or repository evidence resolves the identity with sufficient confidence.