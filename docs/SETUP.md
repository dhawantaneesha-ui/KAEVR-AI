# KAEVR-AI Development Setup

## Purpose

This document describes the common development setup for all KAEVR-AI team members.

Every team member should follow the same basic setup so that all four modules can be developed and integrated consistently.

---

## Project Modules

KAEVR-AI is divided into four modules:

```text
Module 1
Ingestion & Log Intelligence
        |
        v
Module 2
Detection & Risk Engine
        |
        v
Module 3
Supervisor AI & Response
        |
        v
Module 4
SOC Dashboard & Analytics
```

Each team member primarily develops inside their assigned module.

---

## Required Development Tools

All team members should have the following tools available:

- Git
- GitHub account with access to the KAEVR-AI repository
- Antigravity development environment
- Claude Code
- Python
- Docker Desktop
- A terminal / command-line environment
- A modern web browser

Frontend-specific tools may be added once the frontend stack is finalized.

---

## Repository

Shared repository:

```text
KAEVR-AI
```

The repository contains:

```text
KAEVR-AI/
|
|-- docs/
|
|-- ingestion/
|
|-- detection/
|
|-- supervisor/
|
|-- frontend/
|
|-- scripts/
|
|-- docker-compose.yml
|-- .env.example
|-- .gitignore
`-- README.md
```

---

## Important Documents

Before starting development, every team member should read:

```text
docs/ARCHITECTURE.md
docs/CONTRACT.md
docs/GIT_WORKFLOW.md
docs/SETUP.md
```

### ARCHITECTURE.md

Defines:

- Overall KAEVR-AI architecture
- Module responsibilities
- Data flow
- Shared infrastructure

### CONTRACT.md

Defines:

- Module 1 → Module 2 schema
- Module 2 → Module 3 schema
- Module 3 → Module 4 schema
- Shared field names
- Evidence traceability rules

### GIT_WORKFLOW.md

Defines:

- Branching rules
- Commit rules
- Pull Request workflow
- Module ownership
- Shared file rules

---

## GitHub Access

Each team member must have collaborator access to the shared KAEVR-AI repository.

Do not create separate independent repositories for individual modules.

All four modules belong inside the same shared repository.

---

## Clone the Repository

Each developer should clone the shared repository onto their local machine.

The exact clone command will use the repository URL shown on GitHub.

Example format:

```bash
git clone <KAEVR-AI-repository-url>
```

Then move into the project directory:

```bash
cd KAEVR-AI
```

---

## Branch Setup

Development should not normally happen directly on `main`.

Each team member should create their own module branch from the latest `main`.

Recommended naming format:

```text
<name>-<module>
```

Example:

```text
taneesha-detection
```

Other examples:

```text
member-ingestion
member-supervisor
member-frontend
```

The exact branch names should be communicated to the team.

---

## Update Main Before Creating a Branch

Before creating a new branch, make sure the local `main` branch is current.

Typical workflow:

```bash
git checkout main
git pull origin main
```

Then create the module branch:

```bash
git checkout -b <branch-name>
```

Example:

```bash
git checkout -b taneesha-detection
```

---

## Development Environment

The team may use Antigravity as the primary development environment.

After cloning the repository locally, open the KAEVR-AI project directory inside the development environment.

The development environment should point to the root of the repository:

```text
KAEVR-AI/
```

not only to an individual file.

This allows development tools to understand the complete project structure and shared documentation.

---

## Claude Code

Claude Code may be used to assist with development.

Before asking Claude Code to implement a module or feature, it should be given the project context.

At minimum, instruct it to read:

```text
docs/ARCHITECTURE.md
docs/CONTRACT.md
docs/GIT_WORKFLOW.md
```

before making significant changes.

A recommended instruction is:

```text
Read docs/ARCHITECTURE.md, docs/CONTRACT.md, and
docs/GIT_WORKFLOW.md before making changes.

Follow the shared contracts exactly.

Only modify files inside my assigned module unless I explicitly
authorize a shared-file change.
```

AI coding tools must not be allowed to silently change shared schemas or another team member's module.

---

## Python Environment

Backend modules will use Python.

A separate virtual environment should be used instead of installing project dependencies globally.

From the repository root, a virtual environment can be created with:

```bash
python -m venv .venv
```

### Windows

Activate it using:

```bash
.venv\Scripts\activate
```

### macOS / Linux

Activate it using:

```bash
source .venv/bin/activate
```

When activated, the terminal normally displays:

```text
(.venv)
```

before the command prompt.

---

## Python Version

The exact shared Python version should be finalized before backend implementation begins.

All backend team members should use the same major/minor Python version once it is selected.

The finalized version should then be documented here.

---

## Python Dependencies

Each backend module should document its dependencies.

The final dependency strategy will be decided during implementation.

Potential backend packages may include libraries for:

- FastAPI
- Data validation
- Redpanda / Kafka communication
- OpenSearch communication
- Machine learning
- Explainability
- Testing

Do not install unnecessary packages before the module actually requires them.

---

## Environment Variables

Secrets and machine-specific configuration should be stored in a local:

```text
.env
```

file.

The real `.env` file must never be committed to GitHub.

The repository should instead contain:

```text
.env.example
```

with empty placeholders.

Example:

```env
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

REDPANDA_BROKERS=
OPENSEARCH_URL=
```

Only variables actually used by the project should remain in the final `.env.example`.

---

## Secrets Rule

Never commit:

```text
API keys
access tokens
passwords
private credentials
database passwords
cloud credentials
```

Do not paste secrets into:

```text
source code
README files
CONTRACT.md
Git commits
Pull Request descriptions
screenshots
```

---

## Docker

Docker Desktop will be used to run shared infrastructure locally.

Planned shared services include:

```text
Redpanda
OpenSearch
```

Additional services may be added later.

Shared services will eventually be defined in:

```text
docker-compose.yml
```

The final Docker Compose configuration will be added during infrastructure integration.

---

## Redpanda

Redpanda is planned for real-time communication between backend modules.

Current planned topics are:

```text
normalized-events
alerts
incidents
```

The topic definitions must remain consistent with:

```text
docs/CONTRACT.md
```

---

## OpenSearch

OpenSearch is planned for searchable security data.

Current planned data categories are:

```text
events
alerts
incidents
```

Exact index mappings and configuration will be finalized during integration.

---

## FastAPI

Backend modules may expose APIs using FastAPI.

Examples include service status endpoints and backend functionality required by the frontend or other modules.

API routes should be documented inside the owning module.

---

## Module Development

### Module 1

Primary folder:

```text
ingestion/
```

### Module 2

Primary folder:

```text
detection/
```

### Module 3

Primary folder:

```text
supervisor/
```

### Module 4

Primary folder:

```text
frontend/
```

Each developer should primarily modify only their assigned module.

---

## Detection Module Example

The Detection & Risk Engine may eventually contain:

```text
detection/
|
|-- sigma_rules/
|
|-- ioc/
|
|-- risk_model/
|
|-- tests/
|
|-- aggregator.py
|-- mitre_map.py
|-- api.py
`-- README.md
```

The exact implementation will be developed inside the detection branch.

---

## Starting Development

Before coding, verify:

```text
1. Repository has been cloned.

2. You are inside the KAEVR-AI directory.

3. You are NOT developing directly on main.

4. Your own branch is active.

5. You have read CONTRACT.md.

6. Your local environment is configured.

7. Required secrets are stored locally.

8. You understand which module you own.
```

---

## Typical Development Workflow

```text
GitHub Repository
        |
        v
Clone Locally
        |
        v
Open KAEVR-AI in Development Environment
        |
        v
Read Architecture + Contract
        |
        v
Create / Switch to Own Branch
        |
        v
Configure Local Environment
        |
        v
Develop Assigned Module
        |
        v
Test
        |
        v
Commit
        |
        v
Push
        |
        v
Pull Request
        |
        v
Review
        |
        v
Merge into main
```

---

## Running the Full System

The exact command for running the complete KAEVR-AI platform will be added after the Docker Compose and service configuration is implemented.

The intended goal is to make local startup as simple as possible, ideally through shared Docker Compose configuration.

---

## Setup Changes

If installation requirements or shared versions change, update this document.

Changes that affect all developers should be communicated to the team before they are merged.

---

## Source of Truth

Overall architecture:

```text
docs/ARCHITECTURE.md
```

Shared data schemas:

```text
docs/CONTRACT.md
```

Git collaboration rules:

```text
docs/GIT_WORKFLOW.md
```

Development setup:

```text
docs/SETUP.md
```
