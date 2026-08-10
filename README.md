# KAEVR-AI

KAEVR-AI is an evidence-first AI-powered cybersecurity platform for real-time log intelligence, threat detection, explainable risk scoring, AI-assisted investigation, response recommendations, and SOC analytics.

The system is designed as four independently owned but contract-driven modules.

---

## Project Architecture

```text
Security Data Sources
        |
        v
+----------------------------------+
| Module 1                         |
| Ingestion & Log Intelligence     |
+----------------+-----------------+
                 |
                 | Normalized Events
                 v
+----------------------------------+
| Module 2                         |
| Detection & Risk Engine          |
+----------------+-----------------+
                 |
                 | Alerts + Evidence
                 v
+----------------------------------+
| Module 3                         |
| Supervisor AI & Response         |
+----------------+-----------------+
                 |
                 | Incidents / Decisions
                 v
+----------------------------------+
| Module 4                         |
| SOC Dashboard & Analytics        |
+----------------------------------+
```

---

## Modules

### Module 1 — Ingestion & Log Intelligence

Responsible for:

- Receiving security logs and events
- Parsing raw telemetry
- Normalizing different log formats
- Validating required fields
- Preparing events for downstream detection
- Publishing normalized events

Primary folder:

```text
ingestion/
```

---

### Module 2 — Detection & Risk Engine

Responsible for:

- Sigma-style threat detection
- IOC matching
- Behavioural / ML-based risk analysis
- Explainable AI
- Evidence-backed risk scoring
- MITRE ATT&CK mapping
- Structured alert generation

Primary folder:

```text
detection/
```

---

### Module 3 — Supervisor AI & Response

Responsible for:

- Alert investigation
- Alert correlation
- Supervisor AI reasoning
- Attack timeline reconstruction
- Response recommendations
- AI Security Chat
- Incident report generation

Primary folder:

```text
supervisor/
```

---

### Module 4 — SOC Dashboard & Analytics

Responsible for:

- Real-time alert monitoring
- Incident visualization
- Risk visualization
- MITRE ATT&CK views
- Attack timelines
- Threat intelligence panels
- Security analytics and KPIs
- Real-time notifications
- AI Security Chat interface
- Incident report presentation

Primary folder:

```text
frontend/
```

---

## Core Features

KAEVR-AI includes:

- Threat Detection
- Log Intelligence
- Risk Scoring
- Supervisor AI
- Response Agent
- Explainable AI
- Attack Timeline
- AI Security Chat
- Incident Report Generator
- Threat Intelligence
- MITRE ATT&CK Mapping
- Real-Time Alert Dashboard
- Real-Time Notifications
- Security Analytics

---

## Evidence-First Design

A core principle of KAEVR-AI is that security decisions must be traceable to evidence.

The intended chain is:

```text
Raw Security Event
        |
        v
NormalizedEvent
        |
        v
Alert
        |
        v
Risk Factors + Evidence
        |
        v
Incident
        |
        v
Investigation / Response
```

A risk score should not exist without an explanation of why it was generated.

Every important risk factor should point back to real source events.

---

## Shared Data Flow

```text
Module 1
   |
   | NormalizedEvent
   v
Module 2
   |
   | Alert
   v
Module 3
   |
   | Incident / Decision
   v
Module 4
```

The exact shared schemas are defined in:

```text
docs/CONTRACT.md
```

---

## Planned Technology Stack

Backend and infrastructure:

- Python
- FastAPI
- Redpanda
- OpenSearch
- Docker
- Docker Compose

AI-assisted development:

- Claude Code
- Antigravity

Frontend technology will be finalized by the frontend module owner.

---

## Repository Structure

```text
KAEVR-AI/
|
|-- docs/
|   |-- ARCHITECTURE.md
|   |-- CONTRACT.md
|   |-- GIT_WORKFLOW.md
|   `-- SETUP.md
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

## Documentation

### Architecture

```text
docs/ARCHITECTURE.md
```

Defines the overall system design, responsibilities, and data flow.

### Shared Contracts

```text
docs/CONTRACT.md
```

Defines the data exchanged between modules and is the source of truth for shared field names and schemas.

### Git Workflow

```text
docs/GIT_WORKFLOW.md
```

Defines branch rules, commits, Pull Requests, module ownership, and collaboration rules.

### Development Setup

```text
docs/SETUP.md
```

Defines the common development environment and setup process.

---

## Development Workflow

Normal development should follow:

```text
main
 |
 v
own module branch
 |
 v
development
 |
 v
testing
 |
 v
commit
 |
 v
push
 |
 v
Pull Request
 |
 v
review
 |
 v
main
```

Team members should not use `main` as their normal development branch.

---

## Module Ownership

```text
ingestion/      -> Module 1 owner

detection/      -> Module 2 owner

supervisor/     -> Module 3 owner

frontend/       -> Module 4 owner
```

Each member should primarily work inside their assigned module.

Shared files should be changed carefully and communicated with the team.

---

## Security Rules

Never commit:

- API keys
- Passwords
- Access tokens
- Private credentials
- Database passwords
- Cloud credentials

Real secrets must remain in local environment files.

The repository should only contain safe placeholders such as:

```text
.env.example
```

---

## Current Development Status

The repository is currently being initialized.

Current focus:

```text
Architecture
     |
     v
Shared Contracts
     |
     v
Git Workflow
     |
     v
Development Setup
     |
     v
Module Development
```

Each module will be developed independently and integrated through the shared contracts defined in this repository.
