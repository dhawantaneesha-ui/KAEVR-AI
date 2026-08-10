# Ingestion & Log Intelligence

This module is responsible for receiving, parsing, validating, and normalizing security logs and events before they are sent to the Detection & Risk Engine.

## Responsibilities

- Receive security logs and telemetry.
- Parse raw events.
- Normalize different log formats into the shared `NormalizedEvent` schema.
- Validate required fields.
- Preserve original evidence in the `raw` field.
- Publish normalized events for Module 2.

## Shared Contract

The exact output schema for this module is defined in:

`docs/CONTRACT.md`

This module must not silently change shared field names or data types.
