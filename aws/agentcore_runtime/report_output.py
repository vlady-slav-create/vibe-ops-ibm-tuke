"""Strands output adapter; shared JSON Schema remains the sole report contract."""
from copy import deepcopy

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contracts.schema import SCHEMA, validate_schema
from contracts.security_report import expected_items, validate_report


class ReviewFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=80)
    rule_ids: list[str] = Field(max_length=12)
    assessment: Literal["supported", "unsupported", "uncertain"]
    note: str = Field(max_length=300)


class Review(BaseModel):
    """Reviewer handoff in the graph: capped fields instead of prose, so the summarizer's guardrail-scanned
    input stays small and predictable. ponytail: notes are still model text; drop them if the guardrail still blocks."""
    model_config = ConfigDict(extra="forbid")
    findings: list[ReviewFinding] = Field(max_length=12)
    gaps: list[str] = Field(max_length=6)


class SecurityReport(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    summary: str
    work_items: list[dict]

    @classmethod
    def model_json_schema(cls, **kwargs):
        return {**deepcopy(SCHEMA["$defs"]["report"]), "$defs": deepcopy(SCHEMA["$defs"])}

    @model_validator(mode="after")
    def check_contract(self):
        validate_schema("report", self.model_dump())
        return self


def report_from(result, events):
    if result.stop_reason not in {"end_turn", "tool_use"} or not isinstance(result.structured_output, SecurityReport):
        raise RuntimeError(f"report incomplete or request budget exhausted (stop_reason={result.stop_reason}, structured_output={type(result.structured_output).__name__})")  # enum string and class name only
    report = result.structured_output.model_dump()
    # rule_ids are fully determined by the scan and group: set them from evidence, not model output.
    expected = expected_items(events)
    for item in report["work_items"]:
        rules = expected.get((item["event_id"], item["group"]))
        if rules:
            item["rule_ids"] = sorted(rules)
    return validate_report(report, events)