"""Single agent: direct analysis with schema output, no specialist delegation."""
from strands import Agent

from agentcore_runtime.bedrock_analysis import REPORT, RULES, REPORT_LIMITS, observe
from agentcore_runtime.report_output import SecurityReport, report_from


def analyze(events, model, evidence):
    # callback_handler=None: no stdout streaming, so evidence and reports stay out of logs.
    agent = observe(Agent(model=model, system_prompt=RULES + "\n" + "Analyze all evidence directly.\n" + REPORT,
                          callback_handler=None, structured_output_model=SecurityReport))
    return {"report": report_from(agent(evidence, limits=REPORT_LIMITS), events), "specialists": {}}
