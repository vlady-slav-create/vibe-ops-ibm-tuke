"""Fixed Strands Graph: parallel skill-based reviews, then JSON report summarizer."""
from strands import Agent
from strands.hooks import BeforeNodeCallEvent
from strands.multiagent import GraphBuilder
from strands.multiagent.base import Status

from agentcore_runtime.bedrock_analysis import REPORT, RULES, SPECIALISTS, bound_calls, load_skill, specialist, observe
from agentcore_runtime.report_output import SecurityReport, report_from

def analyze(events, model, evidence):
    builder = GraphBuilder()
    reviewers = {}

    for name in SPECIALISTS:
        reviewer, plugin = specialist(name, model)
        reviewers[name] = (reviewer, plugin)
        builder.add_node(reviewer, name)
        builder.set_entry_point(name)

    summarizer = observe(Agent(model=model, name="summarizer", callback_handler=None,
                       structured_output_model=SecurityReport,
                       system_prompt=RULES + "\n" + load_skill("security-coordination").instructions + "\n" + REPORT))
    bound_calls(summarizer, 2)
    builder.add_node(summarizer, "summarizer")
    for name in reviewers:
        builder.add_edge(name, "summarizer")
    builder.set_max_node_executions(3)
    # ponytail: nodes share one runtime and IAM role; split runtimes for independent isolation.
    graph = builder.build()

    def require_reviews(event):
        if event.node_id != "summarizer":
            return
        for name, (reviewer, plugin) in reviewers.items():
            review = graph.state.results.get(name)
            if (review is None or review.status != Status.COMPLETED or
                    review.result.stop_reason != "end_turn" or not str(review).strip() or
                    SPECIALISTS[name] not in plugin.get_activated_skills(reviewer)):
                raise RuntimeError("specialist review failed or required skill was not activated")

    graph.hooks.add_callback(BeforeNodeCallEvent, require_reviews)
    result = graph(evidence)
    if result.status != Status.COMPLETED or set(result.results) != {*reviewers, "summarizer"}:
        raise RuntimeError("security review graph did not complete")
    summary = result.results["summarizer"]
    if summary.status != Status.COMPLETED:
        raise RuntimeError("summarizer did not complete")
    return {"report": report_from(summary.result, events),
            "specialists": {name: str(result.results[name]) for name in reviewers}}
