# Software Supply Chain Data Engineering and Analytics

## Project Overview

This project develops a data pipeline and analytical database for examining software supply chain dependencies and known vulnerabilities in Python packages. It integrates PyPI package metadata and Open Source Vulnerabilities (OSV) advisory records, using MongoDB to store raw JSON documents and Python to transform the data into a PostgreSQL dimensional model.

The resulting database supports SQL analysis of vulnerability exposure, package ownership, dependency relationships, and indirect exposure through dependency chains.

## Data Sources

- **PyPI package metadata:** Package details, published versions, and historical dependency declarations.
- **OSV vulnerability advisories:** Known vulnerability records, severity labels, affected packages, and affected version ranges.

The project uses two input files, `pypi_items.json` and `vulnerabilities.json`. These raw data files are not included in the repository structure below.

## Methodology

### Data ingestion and ETL

Raw JSON records are loaded into MongoDB collections. A Python ETL notebook extracts, cleans, and transforms the nested documents before loading them into PostgreSQL. The transformation includes package-name normalisation, dependency-specifier parsing, advisory deduplication, and handling missing attributes and references to packages outside the dataset.

### Dimensional modelling

The PostgreSQL `ssc` schema follows a Kimball-style dimensional design with three dimension tables and two factless fact tables:

| Table | Contents |
|---|---|
| `dim_package` | Package identifiers and ownership attributes |
| `dim_version` | Published package versions |
| `dim_vulnerability` | Distinct OSV advisories and severity labels |
| `fact_dependency` | Dependencies declared by package versions |
| `fact_affected_range` | Package-version constraints associated with advisories |

The two fact tables share the package dimension, forming a fact constellation. Primary and foreign keys, uniqueness constraints, and indexes support relational consistency and analytical queries.

### SQL analysis

The database is used to investigate four questions:

1. Which packages have the most known vulnerability advisories, by severity?
2. Which organisations own the most packages, and what proportion have at least one linked advisory?
3. Which packages have the most distinct dependent packages, and do they have known vulnerabilities?
4. How many packages are reachable through direct and indirect dependency paths from a selected vulnerable package?

The final question uses a recursive SQL common table expression (CTE) to analyse dependency paths.

## Selected Results

The final ETL run reported:

| Database table | Rows |
|---|---:|
| `dim_package` | 19,989 (including one Unknown member) |
| `dim_version` | 1,858,695 |
| `fact_dependency` | 20,270,815 |
| `dim_vulnerability` | 6,308 |
| `fact_affected_range` | 15,272 |

In the reported analysis, `pytest` had the highest number of distinct dependent packages (4,972). A recursive analysis of the latest-version dependency graph found 13,590 packages reachable from `numpy` within eight hops. These results describe the project dataset and should not be interpreted as complete measurements of the entire PyPI ecosystem or as confirmed exploitability.

## Technologies

- Python and Jupyter Notebook
- MongoDB
- PostgreSQL 15+
- SQL, including recursive CTEs
- Dimensional data modelling and ETL

## Repository Structure

```text
software-supply-chain-data-engineering/
├── notebooks/
│   └── etl_notebook.ipynb
├── sql/
│   └── postgresql_schema_definition.sql
├── docs/
│   ├── Group3_SMM695.pdf
│   └── llm_prompt_document.md
└── README.md
```

## Project Context

Developed as a group project for the MSc Business Analytics **Data Management Systems (SMM695)** module. The database design, implementation, analytical questions, and report were completed collaboratively. Individual contributions are documented in the project report.
