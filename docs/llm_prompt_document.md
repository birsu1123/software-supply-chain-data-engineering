# Software Supply Chain Data Model (PostgreSQL)

## Overview

PostgreSQL 15+ analytical database in schema `ssc`, built from PyPI package metadata and OSV vulnerability advisories. Kimball galaxy schema: three dimension tables (`dim_package`, `dim_version`, `dim_vulnerability`) and two factless fact tables (`fact_dependency`, `fact_affected_range`). Always schema-qualify as `ssc.<table>`.

---

## Recursive CTE Rule (applies to every recursive query)

1. Open with `WITH RECURSIVE` as the very first keyword.
2. Declare **all** CTEs — recursive or not — inside that single block.
3. Use `AS MATERIALIZED` on expensive non-recursive anchors.
4. Use `UNION` (not `UNION ALL`) in the recursive term to deduplicate and prevent infinite loops/cycles.

---

## Tables, Grain, and Caveats

**ssc.dim_package** — one PyPI package.
- `package_key` PK (integer surrogate); `-1` is the Unknown member (never a real package).
- `package_name`, `normalized_package_name` (UNIQUE, lowercase; the business key).
- `author_email` — `'Not Provided'` when missing.
- `organization` — `'No Organization'` when missing.

> **Caveat — Unknown member:** Exclude `package_key = -1` with `<> -1` when counting real packages, organisations, or affected packages.
> **Caveat — Missing values are labels, not NULLs:** Exclude `organization = 'No Organization'` when counting real organisations — these are sentinel labels, not `NULL`s, so `IS NOT NULL` won't filter them.

**ssc.dim_version** — one published version of one package.
- `version_key` PK. `package_key` FK → `dim_package`.
- `version_string`, `uploaded_at`, `size_bytes` (nullable), `yanked` bool, `is_latest` bool.

> **Caveat — Latest-version filtering:** For questions about *current* (rather than historical/all-time) dependencies, filter `dim_version.is_latest = TRUE` on the source version.
> **Caveat — Package-to-version join:** Some packages have no versions. `LEFT JOIN` from `dim_package` to `dim_version` to keep packages with zero matches; `INNER JOIN` only when matched packages are required.

**ssc.fact_dependency** — factless fact. One dependency declared by one (source package, source version) on one target package.
- `dependency_key` PK.
- `source_package_key` FK → `dim_package` (the depending package).
- `source_version_key` FK → `dim_version` (the depending version).
- `target_package_key` FK → `dim_package`, or `-1` if the target is outside the dataset.
- `target_package_name` — normalised name of the dependency.

> **Caveat — Dependants (in-degree):** Use `COUNT(DISTINCT source_package_key)`. The grain is per source *version*, so plain `COUNT(*)` or `COUNT(source_package_key)` overcounts repeated source packages.
> **Caveat — External dependency targets share key `-1`:** When grouping targets, `GROUP BY target_package_name`, never `target_package_key` (all external targets collapse into one `-1` group). Add `WHERE target_package_key <> -1` when only real, in-dataset packages matter.
> **Caveat — "Most depended-upon packages" questions:** For questions like "which packages does the ecosystem depend on most", "most popular dependency targets", or "which libraries have the most dependents", compute `COUNT(DISTINCT source_package_key)` grouped by target package. **Do NOT filter on `dim_version.is_latest`** — these cover ecosystem-wide relationships across all versions. Apply the latest-version filter only when the question explicitly asks about the current dependency graph or ecosystem.

**ssc.dim_vulnerability** — one distinct OSV advisory (unique `osv_id`).
- `vulnerability_key` PK.
- `osv_id` UNIQUE (e.g. GHSA-…, CVE-…, PYSEC-…).
- `summary`, `details` (nullable).
- `severity_label` — one of `CRITICAL`, `HIGH`, `MODERATE`, `MEDIUM`, `LOW`, or `'UNKNOWN'`.
- `modified_date` (nullable).

> **Caveat — Severity grouping:** `MODERATE` and `MEDIUM` are the same level; bucket them together (e.g. via `CASE`) before aggregating by severity.
> **Caveat — Unclassified severity:** Treat `severity_label = 'UNKNOWN'` as unclassified, not missing/NULL — don't drop it silently unless the question asks about classified severities only.

**ssc.fact_affected_range** — factless fact. One affected-version constraint of one advisory for one package.
- `range_key` PK.
- `vulnerability_key` FK → `dim_vulnerability`.
- `package_key` FK → `dim_package`, or `-1` if outside the dataset.
- `affected_package_name` (normalised).
- `introduced_version`, `fixed_version`, `affected_version` (all nullable).

> **Caveat — Advisories per package:** Use `COUNT(DISTINCT vulnerability_key)`. One advisory produces multiple rows — one per introduced/fixed range or pinned version — so `COUNT(*)` overcounts advisories.
> **Caveat — Range vs pinned version:** A row uses either a range (`introduced_version` and/or `fixed_version`) or a pinned `affected_version`, never both. `fixed_version IS NULL` with `introduced_version` set means affected from that version onward, no fix recorded in that branch.
> **Caveat — Bare advisory-package links:** Rows with all three version columns NULL record only that the advisory covers the package. They still count for "has a vulnerability" questions, so don't filter them out with version-column `IS NOT NULL` predicates.
> **Caveat — Package-to-vulnerability join:** Some packages have no vulnerabilities. `LEFT JOIN` from `dim_package` through `fact_affected_range` to keep packages with zero matches; `INNER JOIN` only when vulnerable packages are required.

---

## Join Keys

| From | Key | To |
|---|---|---|
| `dim_version.package_key` | = | `dim_package.package_key` |
| `fact_dependency.source_package_key` | = | `dim_package.package_key` |
| `fact_dependency.target_package_key` | = | `dim_package.package_key` |
| `fact_dependency.source_version_key` | = | `dim_version.version_key` |
| `fact_affected_range.package_key` | = | `dim_package.package_key` |
| `fact_affected_range.vulnerability_key` | = | `dim_vulnerability.vulnerability_key` |

> **Caveat — No direct package↔vulnerability link:** `dim_package` and `dim_vulnerability` have **no direct link**; always join through `fact_affected_range`.

---

## Root Package for Exposure Analysis

> **Default root package:** Unless the user names a different package, treat **`numpy`** (`normalized_package_name = 'numpy'`) as the known vulnerable root package for any "transitive/indirect exposure through the dependency chain" question. Resolve it via:
> ```sql
> SELECT package_key FROM ssc.dim_package WHERE normalized_package_name = 'numpy'
> ```
> A package is "exposed" if it depends, directly or transitively, on the root package. Always report each exposed package's hop count (shortest path).

> **Companion reporting convention:** Every transitive exposure answer **must produce two separate query results in this exact order**:
> 1. **Detail list** — each exposed package with its shortest hop distance (`LIMIT 15` for display), using the recursive join example below.
> 2. **Hop-distribution summary** — reuse the same `edges` and `exposed` CTEs, wrap `exposed` in a subquery computing `MIN(depth)` per package, then group by that minimum with `COUNT(*)` for packages per hop distance, ordered ascending. Report the count sum as Total and the max hop as Max depth reached. Never give the detail list without this summary.

---

## Short Join Examples

**Distinct advisories per package** *(applies: exclude `-1`, `COUNT(DISTINCT vulnerability_key)`)*:
```sql
SELECT dp.package_name,
       COUNT(DISTINCT dv.vulnerability_key) AS total_advisories
FROM ssc.dim_package dp
JOIN ssc.fact_affected_range far ON far.package_key = dp.package_key
JOIN ssc.dim_vulnerability dv    ON dv.vulnerability_key = far.vulnerability_key
WHERE dp.package_key <> -1
GROUP BY dp.package_name
ORDER BY total_advisories DESC;
```

**Transitive dependants — detail list (recursive, hop-counted, LIMIT 15)** *(applies: recursive CTE rule, exclude `-1`; always follow with hop-distribution summary from companion reporting convention above)*:
```sql
WITH RECURSIVE
edges AS MATERIALIZED (
    SELECT DISTINCT d.source_package_key AS src,
                    d.target_package_key AS dst
    FROM ssc.fact_dependency d
    JOIN ssc.dim_version v ON v.version_key = d.source_version_key AND v.is_latest
    WHERE d.target_package_key <> -1
      AND d.source_package_key <> d.target_package_key
),
exposed (pkg, depth) AS (
    SELECT src, 1
    FROM edges
    WHERE dst = (SELECT package_key FROM ssc.dim_package
                 WHERE normalized_package_name = 'numpy')
    UNION
    SELECT e.src, x.depth + 1
    FROM exposed x
    JOIN edges e ON e.dst = x.pkg
    WHERE x.depth < 20
)
SELECT p.package_name, MIN(x.depth) AS shortest_hops
FROM exposed x
JOIN ssc.dim_package p ON p.package_key = x.pkg
GROUP BY p.package_name
ORDER BY shortest_hops, p.package_name
LIMIT 15;
```
