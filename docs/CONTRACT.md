# KAEVR-AI Shared Data Contract

## Purpose

This document defines the shared data exchanged between the four KAEVR-AI modules.

It is the source of truth for inter-module communication.

The system follows this flow:

```text
Module 1
Ingestion & Log Intelligence
        |
        | NormalizedEvent
        v
Module 2
Detection & Risk Engine
        |
        | Alert
        v
Module 3
Supervisor AI & Response
        |
        | Incident / Decision
        v
Module 4
SOC Dashboard & Analytics
```

All team members must follow the schemas defined in this document.

A module must not silently rename, remove, or change the type of a shared field.

If a shared contract needs to change, the change must first be discussed with the team.

---

# Contract 1 — Module 1 to Module 2

## Message Type

`NormalizedEvent`

## Purpose

Module 1 receives raw security telemetry and converts it into a common normalized format.

Module 2 consumes these normalized events for threat detection and risk analysis.

---

## Required Event Structure

```json
{
  "event_id": "evt-123",
  "timestamp": "2026-08-10T12:30:00Z",
  "source": "sysmon",
  "host": "PC-101",
  "user": "admin",
  "event_type": "process_creation",
  "severity_hint": "medium",
  "raw": {},
  "normalized": {}
}
```

---

## Required Fields

### `event_id`

Type:

```text
string
```

A unique identifier for the security event.

Example:

```text
evt-123
```

---

### `timestamp`

Type:

```text
string
```

Timestamp of the original security event.

Use ISO 8601 UTC format whenever possible.

Example:

```text
2026-08-10T12:30:00Z
```

---

### `source`

Type:

```text
string
```

Identifies where the event originated.

Examples:

```text
sysmon
windows
linux
firewall
application
web_server
```

---

### `host`

Type:

```text
string | null
```

Hostname or endpoint associated with the event.

Example:

```text
PC-101
```

---

### `user`

Type:

```text
string | null
```

User associated with the event, when available.

Example:

```text
admin
```

---

### `event_type`

Type:

```text
string
```

Normalized type of the security event.

Examples:

```text
process_creation
login_attempt
network_connection
file_event
authentication
privilege_change
```

---

### `severity_hint`

Type:

```text
string
```

A preliminary severity indication from the ingestion layer.

Allowed values:

```text
low
medium
high
critical
unknown
```

This is only a hint.

Module 2 calculates the final risk score independently.

---

### `raw`

Type:

```text
object
```

Contains the original or minimally processed source event.

This field preserves the original evidence for investigation and traceability.

---

### `normalized`

Type:

```text
object
```

Contains standardized security attributes extracted from the original event.

Depending on the event type, it may contain fields such as:

```json
{
  "process_name": "powershell.exe",
  "command_line": "powershell -enc ...",
  "parent_process": "cmd.exe",
  "src_ip": "10.0.0.5",
  "dst_ip": "8.8.8.8",
  "src_port": 51000,
  "dst_port": 443,
  "domain": "example.com",
  "url": "https://example.com/path",
  "file_name": "payload.exe",
  "file_hash": "abc123...",
  "action": "allowed",
  "status": "success"
}
```

Not every normalized field is required for every event.

Module 1 should provide whichever fields are available and relevant to the event.

---

# Contract 2 — Module 2 to Module 3

## Message Type

`Alert`

## Purpose

Module 2 analyzes normalized events using detection rules, IOC matching, behavioural analysis, explainability, risk scoring, and MITRE ATT&CK mapping.

When suspicious activity is identified, Module 2 produces an evidence-backed alert for Module 3.

---

## Required Alert Structure

```json
{
  "alert_id": "alert-456",
  "created_at": "2026-08-10T12:30:01Z",
  "source_event_ids": [
    "evt-123"
  ],
  "rule_matched": "suspicious_encoded_powershell",
  "risk_score": 91,
  "risk_factors": [
    {
      "factor": "Encoded PowerShell execution detected",
      "weight": 0.40,
      "evidence_event_id": "evt-123"
    },
    {
      "factor": "Known malicious destination IP",
      "weight": 0.30,
      "evidence_event_id": "evt-123"
    }
  ],
  "mitre_attack": [
    "T1059.001"
  ],
  "status": "new"
}
```

---

## Required Fields

### `alert_id`

Type:

```text
string
```

Unique identifier of the generated alert.

---

### `created_at`

Type:

```text
string
```

Timestamp when Module 2 generated the alert.

Use ISO 8601 UTC format.

---

### `source_event_ids`

Type:

```text
array[string]
```

Contains the IDs of security events used to generate the alert.

Example:

```json
[
  "evt-123",
  "evt-124"
]
```

This field creates traceability between an alert and the original evidence.

---

### `rule_matched`

Type:

```text
string | null
```

Primary detection rule responsible for the alert.

Example:

```text
suspicious_encoded_powershell
```

If no Sigma-style rule generated the alert and the alert originated from another detection mechanism, this field may be `null`.

---

### `risk_score`

Type:

```text
integer
```

Final calculated security risk.

Allowed range:

```text
0 - 100
```

Suggested interpretation:

```text
0 - 29    Low
30 - 59   Medium
60 - 79   High
80 - 100  Critical
```

The numerical score remains the source value.

Severity labels can be derived from it.

---

### `risk_factors`

Type:

```text
array[object]
```

Explains why the risk score was generated.

Each risk factor must contain:

```json
{
  "factor": "Known malicious destination IP",
  "weight": 0.30,
  "evidence_event_id": "evt-123"
}
```

Required fields inside each risk factor:

```text
factor
weight
evidence_event_id
```

---

## Evidence-First Requirement

Every meaningful risk factor must point to real evidence using:

```text
evidence_event_id
```

For example:

```text
Risk Factor:
Encoded PowerShell execution

Evidence:
evt-123
```

Module 2 must not generate unexplained high-risk scores without supporting evidence.

---

### `mitre_attack`

Type:

```text
array[string]
```

Contains relevant MITRE ATT&CK technique IDs.

Example:

```json
[
  "T1059.001",
  "T1110"
]
```

---

### `status`

Type:

```text
string
```

Initial alert status.

Allowed initial value:

```text
new
```

Module 3 may later move the alert through the incident investigation lifecycle.

---

# Contract 3 — Module 3 to Module 4

## Message Type

`Incident`

## Purpose

Module 3 consumes alerts from Module 2, correlates evidence, reconstructs attack activity, performs AI-assisted investigation, generates response recommendations, and produces an incident representation for the frontend.

---

## Incident Structure

```json
{
  "incident_id": "inc-789",
  "created_at": "2026-08-10T12:35:00Z",
  "updated_at": "2026-08-10T12:40:00Z",
  "title": "Suspicious PowerShell activity detected",
  "summary": "Encoded PowerShell execution contacted a known malicious destination.",
  "severity": "critical",
  "confidence": 0.94,
  "status": "investigating",
  "alert_ids": [
    "alert-456"
  ],
  "evidence_event_ids": [
    "evt-123"
  ],
  "mitre_attack": [
    "T1059.001"
  ],
  "timeline": [
    {
      "timestamp": "2026-08-10T12:30:00Z",
      "event_id": "evt-123",
      "description": "Encoded PowerShell process executed"
    }
  ],
  "recommended_actions": [
    {
      "action": "block_ip",
      "target": "185.10.10.10",
      "reason": "Destination identified as malicious",
      "requires_approval": true
    }
  ]
}
```

---

## Core Incident Fields

### `incident_id`

Unique identifier for the incident.

---

### `created_at`

Timestamp when the incident was created.

---

### `updated_at`

Timestamp of the most recent incident update.

---

### `title`

Short human-readable incident title.

---

### `summary`

AI-generated or system-generated explanation of the incident.

The summary should be grounded in actual alert and event evidence.

---

### `severity`

Allowed values:

```text
low
medium
high
critical
```

---

### `confidence`

Type:

```text
number
```

Allowed range:

```text
0.0 - 1.0
```

Represents Module 3's confidence in its incident-level assessment.

---

### `status`

Suggested values:

```text
new
investigating
contained
resolved
dismissed
```

---

### `alert_ids`

Type:

```text
array[string]
```

Alerts associated with the incident.

---

### `evidence_event_ids`

Type:

```text
array[string]
```

Original security events supporting the incident.

This preserves evidence traceability all the way from Module 1 to Module 4.

---

### `mitre_attack`

Type:

```text
array[string]
```

Combined MITRE ATT&CK techniques associated with the incident.

---

### `timeline`

Type:

```text
array[object]
```

Chronological reconstruction of important attack events.

Example:

```json
{
  "timestamp": "2026-08-10T12:30:00Z",
  "event_id": "evt-123",
  "description": "Encoded PowerShell process executed"
}
```

---

### `recommended_actions`

Type:

```text
array[object]
```

Response actions proposed by the Supervisor / Response Agent.

Example:

```json
{
  "action": "block_ip",
  "target": "185.10.10.10",
  "reason": "Destination identified as malicious",
  "requires_approval": true
}
```

Actions that modify real systems should default to:

```text
requires_approval = true
```

unless the team explicitly implements an approved automated response policy.

---

# Shared Streaming Contract

The planned real-time communication flow is:

```text
Module 1
   |
   | normalized-events
   v
Module 2
   |
   | alerts
   v
Module 3
   |
   | incidents
   v
Module 4
```

Planned Redpanda topics:

```text
normalized-events
alerts
incidents
```

These names should remain consistent across services unless the team agrees to change them.

---

# OpenSearch Data

The planned searchable data categories are:

```text
events
alerts
incidents
```

The exact OpenSearch configuration and mappings may be added during infrastructure implementation.

Application code should not contain hard-coded credentials.

---

# Contract Compatibility Rules

The following rules apply to all modules:

1. Do not silently rename shared fields.
2. Do not silently delete required fields.
3. Do not change a field's data type without team agreement.
4. Additional module-specific internal fields are allowed.
5. Shared schema changes must be communicated before implementation.
6. Timestamps should use ISO 8601 UTC format whenever possible.
7. IDs must remain unique within their entity type.
8. Evidence references must point to real event IDs.
9. Secrets and API keys must never be included in shared event messages.
10. Shared contracts should remain backward compatible whenever practical.

---

# Evidence Traceability

KAEVR-AI should preserve this evidence chain:

```text
Raw Security Event
        |
        v
NormalizedEvent
 event_id
        |
        v
Alert
 source_event_ids
 risk_factors
 evidence_event_id
        |
        v
Incident
 alert_ids
 evidence_event_ids
        |
        v
SOC Dashboard / Investigation
```

This evidence chain is a core architectural principle of KAEVR-AI.

The system should always make it possible to answer:

```text
Why was this alert generated?

Which original event caused it?

Why was this incident considered dangerous?

What evidence supports the AI's recommendation?
```

---

# Source of Truth

For shared message formats and field names:

`docs/CONTRACT.md`

For overall system design:

`docs/ARCHITECTURE.md`

For Git collaboration rules:

`docs/GIT_WORKFLOW.md`

For environment and local setup:

`docs/SETUP.md`
