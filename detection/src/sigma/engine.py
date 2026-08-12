"""
Sigma-Style Rule Engine — Module 2: Detection & Risk Engine

NOTE ON SIGMA SUBSET COMPATIBILITY & STATEFUL CORRELATION:
This module implements a deterministic, lightweight subset of the Sigma rule specification
tailored for single-event execution within KAEVR-AI. Supported features include single-event selection blocks,
field modifier chains (|endswith, |contains, |startswith), case-insensitive value matching, and MITRE ATT&CK
tag extraction.

MODULE 2 BRUTE-FORCE ARCHITECTURE NOTE:
A single failed authentication event is an individual indicator signal, NOT a confirmed brute-force attack.
Primary brute-force threat detection belongs to Module 2 (Detection & Risk Engine) and requires a stateful,
windowed correlation component (tracking N failures for the same user/IP within time window T). This stateful
correlation component will be implemented inside Module 2 in a later phase. Single-event Sigma rules match
atomic event attributes only.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml
from pydantic import BaseModel, Field

from detection.src.models import NormalizedEvent


class SigmaRuleMatch(BaseModel):
    """
    Structured metadata returned when a Sigma rule matches a NormalizedEvent.
    Independent of shared Alert schema.
    """
    rule_id: str
    title: str
    severity: str
    mitre_attack: List[str] = Field(default_factory=list)


class SigmaEngine:
    """
    Evaluates YAML Sigma-style rules against single NormalizedEvent objects.
    Designed for zero network calls, safe field access, and exception safety.
    """

    def __init__(self, rules_dir: Optional[Union[str, Path]] = None) -> None:
        if rules_dir is None:
            # Default to detection/src/sigma/rules/
            current_dir = Path(__file__).parent
            rules_dir = current_dir / "rules"
        
        self.rules_dir = Path(rules_dir)
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()

    def load_rules(self) -> int:
        """
        Loads all .yml and .yaml rule files from the specified rules directory.
        Handles missing files and malformed YAML gracefully without crashing.
        Returns the number of successfully loaded valid rules.
        """
        self.rules.clear()
        if not self.rules_dir.exists() or not self.rules_dir.is_dir():
            return 0

        for file_path in self.rules_dir.glob("*"):
            if file_path.suffix.lower() in (".yml", ".yaml"):
                self.load_rule_file(file_path)

        return len(self.rules)

    def load_rule_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Loads a single YAML rule file and validates basic required structure.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                rule_data = yaml.safe_load(f)

            if not isinstance(rule_data, dict):
                return None

            # Validate basic required fields
            if "id" not in rule_data or "detection" not in rule_data:
                return None

            self.rules.append(rule_data)
            return rule_data
        except Exception:
            # Handle malformed YAML or IO errors safely
            return None

    def evaluate(self, event: NormalizedEvent) -> List[SigmaRuleMatch]:
        """
        Evaluates all loaded rules against a NormalizedEvent.
        Returns a list of structured SigmaRuleMatch objects for matched rules.
        """
        matches: List[SigmaRuleMatch] = []
        for rule in self.rules:
            match = self.evaluate_rule(rule, event)
            if match:
                matches.append(match)
        return matches

    def evaluate_rule(self, rule: Dict[str, Any], event: NormalizedEvent) -> Optional[SigmaRuleMatch]:
        """
        Evaluates a single rule dictionary against a NormalizedEvent.
        Returns a SigmaRuleMatch if the event matches rule conditions, else None.
        """
        detection = rule.get("detection")
        if not isinstance(detection, dict):
            return None

        selection = detection.get("selection")
        if not isinstance(selection, dict):
            return None

        # Evaluate selection block (AND of all field specifications in selection)
        if not self._evaluate_selection(selection, event):
            return None

        # Extract MITRE ATT&CK tags from rule metadata if present
        mitre_tags = self._extract_mitre_attack(rule.get("tags", []))

        return SigmaRuleMatch(
            rule_id=str(rule.get("id", "unknown")),
            title=str(rule.get("title", "Untitled Rule")),
            severity=str(rule.get("severity", "medium")),
            mitre_attack=mitre_tags,
        )

    def _evaluate_selection(self, selection: Dict[str, Any], event: NormalizedEvent) -> bool:
        """
        Evaluates a selection map against event fields.
        All entries in selection map must evaluate to True (AND logic).
        """
        for field_spec, target_value in selection.items():
            if not self._evaluate_field_condition(field_spec, target_value, event):
                return False
        return True

    def _evaluate_field_condition(
        self, field_spec: str, target_value: Any, event: NormalizedEvent
    ) -> bool:
        """
        Evaluates a single field condition (e.g. 'normalized.process_name|endswith')
        against the event safely. Returns False if field is missing or None.
        """
        # Parse field path and optional modifier
        if "|" in field_spec:
            field_path, modifier = field_spec.split("|", 1)
        else:
            field_path, modifier = field_spec, "exact"

        val = self._get_field_value(field_path, event)
        if val is None:
            return False

        str_val = str(val).lower()

        # Handle list of target values (OR logic for list elements)
        targets = target_value if isinstance(target_value, list) else [target_value]

        if modifier == "endswith":
            return any(str_val.endswith(str(t).lower()) for t in targets)
        elif modifier == "startswith":
            return any(str_val.startswith(str(t).lower()) for t in targets)
        elif modifier == "contains":
            return any(str(t).lower() in str_val for t in targets)
        elif modifier in ("exact", "equals"):
            return any(str_val == str(t).lower() for t in targets)
        else:
            # Fallback to exact comparison for unknown modifiers
            return any(str_val == str(t).lower() for t in targets)

    def _get_field_value(self, field_path: str, event: NormalizedEvent) -> Optional[Any]:
        """
        Safely retrieves field value from NormalizedEvent top-level attributes,
        'normalized' dictionary, or 'raw' dictionary without throwing errors.
        """
        if field_path.startswith("normalized."):
            key = field_path.split("normalized.", 1)[1]
            return event.normalized.get(key)
        elif field_path.startswith("raw."):
            key = field_path.split("raw.", 1)[1]
            return event.raw.get(key)
        
        # Check top-level event attributes
        if hasattr(event, field_path):
            val = getattr(event, field_path, None)
            if val is not None:
                return val

        # Fallback check inside normalized dict
        return event.normalized.get(field_path)

    @staticmethod
    def _extract_mitre_attack(tags: Any) -> List[str]:
        """
        Extracts MITRE ATT&CK technique codes from rule tags array.
        Example: ['attack.t1059.001', 'attack.execution'] -> ['T1059.001']
        """
        if not isinstance(tags, list):
            return []

        mitre_ids: List[str] = []
        for tag in tags:
            if not isinstance(tag, str):
                continue
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.t"):
                # Extract technique ID e.g. attack.t1059.001 -> T1059.001
                tech_id = tag_lower.split("attack.", 1)[1].upper()
                if tech_id not in mitre_ids:
                    mitre_ids.append(tech_id)
        return mitre_ids
