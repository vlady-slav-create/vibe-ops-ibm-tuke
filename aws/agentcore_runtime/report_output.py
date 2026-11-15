"""Strands output adapter; shared JSON Schema remains the sole report contract."""
from copy import deepcopy

from pydantic import BaseModel, ConfigDict, model_validator

from contracts.schema import SCHEMA, validate_schema
from contracts.security_report import validate_report


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
        raise RuntimeError("report incomplete or request budget exhausted")
    return validate_report(result.structured_output.model_dump(), events)