"""Model-directed Strands orchestrator: specialists exposed as agent tools."""
from strands import Agent
from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent

from agentcore_runtime.bedrock_analysis import REPORT, RULES, SPECIALISTS, ORCHESTRATOR_LIMITS, load_skill, specialist, observe
from agentcore_runtime.report_output import SecurityReport, report_from


def analyze(events, model, evidence):
    reviewers = {name: specialist(name, model, [{"role": "user", "content": evidence}])
                 for name in SPECIALISTS}
    reports = {}
    attempted = set()
    failed = set()

    agent = observe(Agent(model=model, callback_handler=None, structured_output_model=SecurityReport,
                  system_prompt=RULES + "\n" + load_skill("security-orchestration").instructions + "\n" + REPORT,
                  tools=[reviewer.as_tool() for reviewer, _ in reviewers.values()]))

    def once(event):
        name = event.tool_use["name"]
        if name == "SecurityReport":
            return
        if name in attempted:
            failed.add(name)
            event.cancel_tool = "Tool already called; use existing result."
        attempted.add(name)

    def record(event):
        name = event.tool_use["name"]
        if name == "SecurityReport":
            return
        result = event.result
        if not isinstance(result, dict) or result.get("status") != "success":
            failed.add(name)
            return
        if name in reviewers:
            reviewer, plugin = reviewers[name]
            if SPECIALISTS[name] not in plugin.get_activated_skills(reviewer):
                failed.add(name)
                return
        reports[name] = "".join(block.get("text", "") for block in result["content"])
        if not reports[name].strip():
            failed.add(name)

    agent.hooks.add_callback(BeforeToolCallEvent, once)
    agent.hooks.add_callback(AfterToolCallEvent, record)
    result = agent(evidence, limits=ORCHESTRATOR_LIMITS)
    if failed:
        raise RuntimeError("orchestrator tool failed or required skill was not activated")
    return {"report": report_from(result, events), "specialists": reports}
