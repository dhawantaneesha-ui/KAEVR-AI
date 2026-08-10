# KAEVR-AI Git Workflow

## Purpose

This document defines how the KAEVR-AI team will use Git and GitHub.

The goal is to allow all four team members to work independently on their modules without accidentally breaking another module or the shared `main` branch.

---

## Main Rule

The `main` branch represents the latest stable integrated version of KAEVR-AI.

Team members should not use `main` as their normal development branch.

Normal development should happen inside individual feature/module branches.

The expected workflow is:

```text
main
 |
 +--> individual branch
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

---

## Module Ownership

The repository is divided into four primary modules.

```text
ingestion/      -> Module 1: Ingestion & Log Intelligence

detection/      -> Module 2: Detection & Risk Engine

supervisor/     -> Module 3: Supervisor AI & Response

frontend/       -> Module 4: SOC Dashboard & Analytics
```

Each team member should primarily make changes inside the folder assigned to them.

---

## Branch Naming

Each team member should create a separate development branch.

Recommended format:

```text
<name>-<module>
```

Examples:

```text
Siddhartha-ingestion
taneesha-detection
Ayan-supervisor
shreya-frontend
```

If the actual team ownership differs, use the same naming pattern with the correct member and module.

---

## Creating a Branch

Each member should create their branch from the latest version of `main`.

Conceptually:

```text
main
 |
 +--> taneesha-detection
 |
 +--> member-ingestion
 |
 +--> member-supervisor
 |
 +--> member-frontend
```

A branch should not be created from another teammate's development branch unless the team intentionally needs that dependency.

---

## Daily Development Rule

Before starting new work, make sure the local repository is up to date.

Then work only on the assigned development branch.

Example:

```text
main
  |
  v
taneesha-detection
  |
  +--> Sigma detection
  |
  +--> IOC matching
  |
  +--> Risk model
  |
  +--> MITRE mapping
```

Do not perform normal feature development directly on `main`.

---

## Folder Ownership Rule

### Module 1 Owner

Primarily edits:

```text
ingestion/
```

### Module 2 Owner

Primarily edits:

```text
detection/
```

### Module 3 Owner

Primarily edits:

```text
supervisor/
```

### Module 4 Owner

Primarily edits:

```text
frontend/
```

A team member should not randomly modify another member's module.

If a change in another module is required for integration, discuss it with that module's owner first.

---

## Shared Files

The following files are shared by the whole team:

```text
docs/
README.md
docker-compose.yml
.env.example
.gitignore
```

Important shared documents include:

```text
docs/ARCHITECTURE.md
docs/CONTRACT.md
docs/GIT_WORKFLOW.md
docs/SETUP.md
```

Changes to shared files should be communicated to the team.

After initial repository setup, shared-file changes should preferably happen through a branch and Pull Request instead of silent direct edits to `main`.

---

## CONTRACT.md Rule

`docs/CONTRACT.md` is the source of truth for communication between modules.

The important flow is:

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

A team member must not silently:

- Rename a shared field.
- Delete a required shared field.
- Change the type of a shared field.
- Change shared topic names.
- Change the meaning of a shared field.

If a contract change is required, discuss it with the team before implementing it.

---

## Commit Guidelines

Commits should represent meaningful checkpoints.

Avoid one giant commit containing the entire module.

Good examples:

```text
feat: implement sigma rule detection

feat: add IOC matching

feat: add risk aggregation

feat: add MITRE mapping

fix: handle missing normalized IP fields

test: add IOC matcher tests

docs: update detection module documentation
```

---

## Recommended Commit Prefixes

Use these prefixes where possible:

```text
feat:   new functionality

fix:    bug fix

test:   tests

docs:   documentation

refactor: internal code improvement

chore:  setup, configuration, or maintenance
```

Example:

```text
feat: add malicious IP IOC matcher
```

---

## Commit Size

Prefer smaller logical commits.

Instead of:

```text
implemented complete detection module
```

prefer:

```text
feat: add sigma detection engine

feat: add IOC matcher

feat: add risk model

feat: add risk aggregator

feat: add MITRE mapping

test: add detection pipeline tests
```

This makes review and debugging easier.

---

## Pull Request Workflow

When a checkpoint is ready:

```text
Individual Branch
       |
       v
     Push
       |
       v
Pull Request
       |
       v
Team Review
       |
       v
Merge into main
```

The Pull Request should clearly describe:

```text
What was added?

What was changed?

How was it tested?

Does it affect another module?

Does it change CONTRACT.md?
```

---

## Pull Request Example

### Title

```text
feat: add IOC matching to detection engine
```

### Description

```text
What changed:
Added malicious IP, domain, and hash matching.

Module:
Detection & Risk Engine

Testing:
Tested using sample normalized events.

Contract impact:
No shared contract changes.

Dependencies:
None.
```

---

## Team Lead Review

The team lead coordinates integration into `main`.

Before merging a Pull Request, check:

```text
1. Is the code in the correct module?

2. Does the PR accidentally modify another member's folder?

3. Does the code follow CONTRACT.md?

4. Are secrets or API keys accidentally included?

5. Has basic testing been completed?

6. Does the PR modify shared files?

7. Will the change break another module?
```

If everything looks correct, the Pull Request can be merged.

---

## Main Branch Safety

Because branch protection may not be available for the current repository configuration, the team will enforce the following rule manually:

```text
DO NOT USE MAIN AS A DEVELOPMENT BRANCH.
```

Normal workflow:

```text
main
 ↓
own branch
 ↓
development
 ↓
commit
 ↓
push
 ↓
Pull Request
 ↓
review
 ↓
merge
```

---

## Handling Merge Conflicts

A merge conflict means Git found changes that cannot be combined automatically.

If a conflict occurs:

```text
Do not randomly delete code.
```

First identify:

```text
Which files conflict?

Who owns those files?

Is a shared contract involved?
```

If the conflict involves another member's module, coordinate with that member before resolving it.

If the conflict involves:

```text
docs/CONTRACT.md
docker-compose.yml
README.md
.env.example
```

the team should resolve it carefully because these are shared files.

---

## Secrets Rule

Never commit real secrets.

Do not commit:

```text
API keys
passwords
tokens
private credentials
database passwords
cloud credentials
```

For example, never commit:

```text
OPENAI_API_KEY=real-secret-key
```

Instead, the repository should contain:

```text
.env.example
```

with placeholders:

```text
OPENAI_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
```

Each developer keeps real values inside their local `.env` file.

The real `.env` file must not be committed.

---

## Integration Rule

A module should communicate with another module through the agreed shared contract rather than depending on another module's internal implementation.

For example:

```text
Module 1
      |
      | NormalizedEvent
      v
Module 2
```

Module 2 should depend on the `NormalizedEvent` contract.

It should not depend on how Module 1 internally parses its logs.

Similarly:

```text
Module 2
      |
      | Alert
      v
Module 3
```

Module 3 should depend on the shared `Alert` format rather than Module 2's internal implementation.

---

## Recommended Team Workflow

```text
                main
                 |
      +----------+----------+----------+
      |          |          |          |
      v          v          v          v
 ingestion   detection  supervisor  frontend
  branch      branch      branch     branch
      |          |          |          |
      v          v          v          v
    code       code       code       code
      |          |          |          |
      v          v          v          v
    test       test       test       test
      |          |          |          |
      v          v          v          v
     PR          PR         PR         PR
      |          |          |          |
      +----------+----------+----------+
                 |
                 v
                main
```

---

## Source of Truth

For architecture:

`docs/ARCHITECTURE.md`

For shared schemas and module communication:

`docs/CONTRACT.md`

For Git and collaboration rules:

`docs/GIT_WORKFLOW.md`

For local development setup:

`docs/SETUP.md`
