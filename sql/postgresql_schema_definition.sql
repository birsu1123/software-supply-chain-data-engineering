-- ssc_schema.sql
-- Standalone schema for the Software Supply Chain (SSC) project.
-- Kept in sync with the CREATE statements in etl_notebook.ipynb.
-- Requires PostgreSQL 15+ (UNIQUE ... NULLS NOT DISTINCT).
-- Kimball "no NULLs": dimension attributes use surrogates; fact foreign keys are NOT NULL,
-- and packages outside our dataset point at the Unknown member (package_key = -1).

CREATE SCHEMA IF NOT EXISTS ssc;

-- 1. dim_package  (conformed dimension)  Grain: one PyPI package.
CREATE TABLE IF NOT EXISTS ssc.dim_package (
    package_key BIGSERIAL PRIMARY KEY,
    package_name TEXT NOT NULL,
    normalized_package_name TEXT NOT NULL UNIQUE,
    author_email TEXT NOT NULL DEFAULT 'Not Provided',
    organization TEXT NOT NULL DEFAULT 'No Organization'
);

-- 2. dim_version  (dimension)  Grain: one published version of a package.
CREATE TABLE IF NOT EXISTS ssc.dim_version (
    version_key BIGSERIAL PRIMARY KEY,
    package_key INT NOT NULL REFERENCES ssc.dim_package(package_key) ON DELETE CASCADE,
    version_string TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ NULL,
    size_bytes BIGINT NULL,
    yanked BOOLEAN DEFAULT FALSE,
    is_latest BOOLEAN DEFAULT FALSE,
    CONSTRAINT unique_package_version UNIQUE (package_key, version_string)
);

-- 3. fact_dependency  (factless fact)  Grain: one dependency declared by a
--    (source package, source version). All FKs NOT NULL; out-of-dataset target -> Unknown (-1).
CREATE TABLE IF NOT EXISTS ssc.fact_dependency (
    dependency_key BIGSERIAL PRIMARY KEY,
    source_package_key INT NOT NULL REFERENCES ssc.dim_package(package_key) ON DELETE CASCADE,
    source_version_key INT NOT NULL REFERENCES ssc.dim_version(version_key) ON DELETE CASCADE,
    target_package_key INT NOT NULL REFERENCES ssc.dim_package(package_key) ON DELETE CASCADE,
    target_package_name TEXT NOT NULL          -- normalized dependency name
);

-- 4. dim_vulnerability  (dimension)  Grain: one distinct OSV advisory (unique osv_id).
CREATE TABLE IF NOT EXISTS ssc.dim_vulnerability (
    vulnerability_key BIGSERIAL PRIMARY KEY,
    osv_id TEXT NOT NULL UNIQUE,
    summary TEXT NULL,
    details TEXT NULL,
    severity_label TEXT NOT NULL DEFAULT 'UNKNOWN',
    modified_date TIMESTAMPTZ NULL
);

-- 5. fact_affected_range  (factless fact)  Grain: one affected-version constraint
--    (a range OR a pinned version) of an advisory for a package.
--    All FKs NOT NULL; out-of-dataset affected package -> Unknown (-1).
CREATE TABLE IF NOT EXISTS ssc.fact_affected_range (
    range_key BIGSERIAL PRIMARY KEY,
    vulnerability_key INT NOT NULL REFERENCES ssc.dim_vulnerability(vulnerability_key) ON DELETE CASCADE,
    package_key INT NOT NULL REFERENCES ssc.dim_package(package_key) ON DELETE CASCADE,
    affected_package_name TEXT NOT NULL,
    introduced_version TEXT NULL,
    fixed_version TEXT NULL,
    affected_version TEXT NULL,
    CONSTRAINT unique_affected_range UNIQUE NULLS NOT DISTINCT
        (vulnerability_key, affected_package_name, introduced_version, fixed_version, affected_version)
);

-- Indexes for the analytical joins / group-bys.
CREATE INDEX IF NOT EXISTS idx_dim_package_normalized_name ON ssc.dim_package(normalized_package_name);
CREATE INDEX IF NOT EXISTS idx_dim_version_is_latest       ON ssc.dim_version(package_key) WHERE is_latest;
CREATE INDEX IF NOT EXISTS idx_fact_dependency_source_pkg  ON ssc.fact_dependency(source_package_key);
CREATE INDEX IF NOT EXISTS idx_fact_dependency_source_ver  ON ssc.fact_dependency(source_version_key);
CREATE INDEX IF NOT EXISTS idx_fact_dependency_target_pkg  ON ssc.fact_dependency(target_package_key);
CREATE INDEX IF NOT EXISTS idx_fact_affected_range_pkg     ON ssc.fact_affected_range(package_key);
CREATE INDEX IF NOT EXISTS idx_fact_affected_range_vuln    ON ssc.fact_affected_range(vulnerability_key);

-- Kimball Unknown member: fact foreign keys use this fixed key (-1) instead of NULL.
INSERT INTO ssc.dim_package
    (package_key, package_name, normalized_package_name, author_email, organization)
VALUES (-1, 'Unknown', '(unknown)', 'Not Provided', 'No Organization')
ON CONFLICT (package_key) DO NOTHING;
