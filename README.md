# MSc Dissertation Project: Comparative Analysis of Security Vulnerabilities in RESTful and GraphQL APIs Through Automated Testing

A lightweight and modular Python-based framework that automates OWASP API Security Top 10 vulnerability testing against REST and GraphQL APIs. It then produces comparative metrics (detection rate, precision, recall, F1, coverage) between the two architectures. Results are also benchmarked against OWASP ZAP and GraphQL Cop.

## Table of Contents

- [MSc Dissertation Project: Comparative Analysis of Security Vulnerabilities in RESTful and GraphQL APIs Through Automated Testing](#msc-dissertation-project-comparative-analysis-of-security-vulnerabilities-in-restful-and-graphql-apis-through-automated-testing)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Testing Targets](#testing-targets)
  - [Architecture](#architecture)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Spin up a target](#spin-up-a-target)
  - [Usage](#usage)
  - [Project Structure](#project-structure)
  - [Analysis \& Metrics](#analysis--metrics)
  - [Current Status](#current-status)
  - [Ethical Considerations](#ethical-considerations)
  - [License](#license)

## Overview

Organisations have increasingly used. both RESTful and GraphQL APIs, and API-related attacks (injection, Broken Object Level Authorization, sensitive data exposure) have also grown. Most existing academic security research studies REST or GraphQL in isolation. This project addresses the gap by implementing an automated testing framework capable of evaluating both architectures under the same methodology, then empirically comparing them.

**Aim:** implement a lightweight and open-source automated testing framework to investigate, compare, and critically evaluate security vulnerabilities in RESTful and GraphQL architectures. The targetted vulnerabilities are based on the [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).

**Objectives:**
- Systematic literature review of API security landscapes for both architectures
- Development of modular framework with API test modules
- Empirical evaluation against intentionally vulnerable applications (detection rate, precision, coverage, execution time)
- Benchmarking against existing tools (OWASP ZAP, GraphQL Cop)
- Documentation of comparative analysis of vulnerability patterns between REST and GraphQL

See `ProposalReport.docx` for the full proposal and methodology.

## Testing Targets

Four intentionally vulnerable applications, each run in its own isolated Docker container:

| App | Type | Documented Vulns | Notes |
|---|---|---|---|
| [VAmPI](https://github.com/erev0s/VAmPI) | REST | 9 | SQLi, BOLA, mass assignment, JWT bypass, RegexDoS, etc. |
| [crAPI](https://github.com/OWASP/crAPI) | REST | 21 | Multi-service (identity/community/workshop + Postgres/Mongo) |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | REST | 111 | Largest single vuln surface; API-testable subset only |
| [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | GraphQL | 23 | Sole GraphQL target — DoS, injection, auth bypass, code exec, recon |

## Architecture

```
Config Layer (config/*.yaml)
        │
        ▼
API Clients (src/utils/) ── REST clients (VAmPI/crAPI/Juice Shop) + GraphQL client (DVGA)
        │
        ▼
Vulnerability Modules (src/vulnerabilities/) ── one module per OWASP category
        │
        ▼
Result Logging (src/utils/results_logger.py) ── RunLogger writes JSONL, tagged by
        assertion role (detection / control / adjacent) and OWASP category
        │
        ▼
Comparative Analysis (src/analysis/) ── detection rate, precision, recall, F1,
        coverage, and benchmark comparison against ZAP / GraphQL Cop
        │
        ▼
Reporting (reports/figures/) ── dissertation charts (coverage, severity distribution)
```

## Getting Started

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- `pip`

### Installation

```bash
git clone <repository-url>
cd <repository-directory>
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

GraphQL Cop (used only for the DVGA benchmark) has no PyPI package and is vendored separately with its own isolated venv:

```bash
git clone https://github.com/dolevf/graphql-cop.git benchmarks/graphql-cop
python3 -m venv benchmarks/graphql-cop/venv
benchmarks/graphql-cop/venv/bin/pip install -r benchmarks/graphql-cop/requirements.txt
```

### Spin up a target

```bash
docker-compose -f docker/docker-compose.vampi.yml up -d
docker-compose -f docker/docker-compose.crapi.yml up -d
docker-compose -f docker/docker-compose.juiceshop.yml up -d
docker-compose -f docker/docker-compose.dvga.yml up -d
```

## Usage

Run a full scan against a configured target:

```bash
python -m src.main --target <config.yaml>
```

Run a vulnerability test by testing environment or by vulnerability category:

```bash
python3 -m src.vulnerabilities.authentication --target <vampi|crapi|all>
python3 -m src.vulnerabilities.authorization --target <vampi|crapi|juiceshop|all>
python3 -m src.vulnerabilities.injection --target <vampi|crapi|all>
python3 -m src.vulnerabilities.data_exposure --target <vampi|juiceshop|all>
python3 -m src.vulnerabilities.rate_limiting --target <vampi|crapi|all>

python3 -m src.vulnerabilities.graphql_auth_bypass --target <dvga|all>
python3 -m src.vulnerabilities.graphql_injection --target dvga
python3 -m src.vulnerabilities.graphql_info_disclosure --target dvga
python3 -m src.vulnerabilities.graphql_dos --target dvga
```

Benchmark against external tools:

```bash
python3 -m benchmarks.zap_runner --target <vampi|crapi|juiceshop|all>
python3 -m benchmarks.graphql_cop_runner --target dvga
```

Regenerate dissertation figures:

```bash
python -m src.analysis.visualization
```

Development tooling:

```bash
pytest tests/       # unit tests
black src/ tests/   # format
flake8 src/ tests/  # lint
mypy src/           # type check
```

## Project Structure

```
.
├── config/            # per-target YAML configuration (gitignored, except ground_truth.yaml)
├── docker/            # one docker-compose file per target + a ZAP daemon compose file
├── benchmarks/        # OWASP ZAP and GraphQL Cop benchmark runners
├── src/
│   ├── utils/         # API clients (REST + GraphQL), config loading, results logger
│   ├── vulnerabilities/ # one module per OWASP API Security Top 10 category
│   └── analysis/      # comparative statistics and dissertation figure generation
├── vulnerable_apps/   # reserved per-target scaffolding (VAmPI/crAPI/Juice Shop/DVGA run via docker/ instead)
├── results/           # scan outputs and logs (gitignored, local only)
├── reports/figures/   # generated dissertation charts (coverage, severity distribution)
├── tests/             # unit tests for the framework itself
└── requirements.txt
```

## Analysis & Metrics

- **Row-level metrics** — detection rate, precision, recall, F1 — computed only from test assertions tagged `detection` or `adjacent`; baseline `control` assertions are excluded, since a failing control usually signals a broken assumption rather than a finding.
- **Vulnerability-level coverage** — tested vs. total documented vulnerabilities per target, measured against `config/ground_truth.yaml`.
- **Benchmark comparison** — this framework's own findings joined against OWASP ZAP and GraphQL Cop results by shared test name.
- **False positive rate** is explicitly out of scope — no known-negative test cases exist yet to measure it against — and is reported as a stated limitation rather than approximated.

Inferential statistics (Mann-Whitney U, Chi-square, Cohen's d) are a stretch goal, attempted only if time remains after core detection-rate and coverage results are complete.

## Current Status

- **REST side:** VAmPI (BOLA, SQLi, JWT weak-signing bypass, debug-endpoint exposure, login rate limiting), crAPI (NoSQLi + SQLi via coupon endpoints), Juice Shop (BOLA, Excessive Data Exposure — API-testable surface only)
- **GraphQL side (DVGA):** Authorization Bypass, Injection, Information Disclosure, and Denial of Service categories implemented per the prioritized test case plan; Code Execution, Reconnaissance, and Miscellaneous categories not yet started
- Full detail and open items: see `Prioritized_Test_Case_Plan.md`

## Ethical Considerations

- All testing is confined to self-hosted, intentionally vulnerable applications in isolated (docker) containers — no involvement of production or third-party systems (Computer Misuse Act 1990)
- Only synthetic/fictional data is used in any test fixtures (Data Protection Act 2018)
- No human participants, surveys, or interviews are involved in this research
- Dependencies and tools comply with OSI-approved open-source licenses (MIT, Apache 2.0, etc.)

## License

See `LICENSE`.