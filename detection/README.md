# Detection & Risk Engine

This module is responsible for detecting suspicious security activity, calculating explainable risk, mapping attacks to MITRE ATT&CK techniques, and generating evidence-backed alerts for the Supervisor AI.

## Responsibilities

- Detect threats using Sigma-style rules.
- Match Indicators of Compromise (IOCs) such as malicious IPs, domains, URLs, and file hashes.
- Perform behavioural / ML-based risk analysis.
- Generate explainable risk factors.
- Calculate a final risk score from 0 to 100.
- Link risk factors to real source events.
- Map detected behaviour to MITRE ATT&CK techniques.
- Generate structured alerts for Module 3.

## Planned Detection Pipeline

```text
              Normalized Event
                     |
          +----------+----------+
          |                     |
          v                     v
   Sigma Detection         IOC Matching
          |                     |
          +----------+----------+
                     |
                     v
              ML Risk Analysis
                     |
                     v
               Explainability
                     |
                     v
               Risk Aggregator
                     |
                     v
            MITRE ATT&CK Mapping
                     |
                     v
              Structured Alert
```

## Planned Structure

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

The exact implementation structure may evolve during development.

## Evidence-First Rule

Every meaningful risk factor must be supported by real evidence.

Example:

```text
Risk Factor
Known malicious destination IP
        |
        v
Evidence Event
evt-123
```

The module should not generate unexplained high-risk scores.

## Input

Module 2 consumes:

```text
NormalizedEvent
```

from Module 1.

## Output

Module 2 produces:

```text
Alert
```

for Module 3.

The exact shared schemas and field names are defined in:

`docs/CONTRACT.md`

## Important Rule

This module must follow `docs/CONTRACT.md` and must not silently change shared field names, message formats, or topic names.
