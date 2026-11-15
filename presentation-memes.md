# Meme suggestions — use-case 2 onward

## Added: SpongeBob panels on architecture slides

Character images and short descriptions sit to the right of the three architecture diagrams. Separate character slides were removed.

| Mode | Character / existing template | Description |
| --- | --- | --- |
| `single` | Supplied `/workspaces/project/image copy.png`: multitasking SpongeBob | One agent does every job; no specialist delegation. |
| `orchestrator` | Supplied `ec3950f3-d71d-4c94-abda-8cf2178234e5_text_hi.gif`: Mr. Krabs delegates | Central lead selects specialists when useful; neither both reviews nor parallel execution is guaranteed. Original GIF animation retained. |
| `graph` | Supplied `/workspaces/project/image copy 2.png`: Squidward and SpongeBob | AppSec and quality reviews run in parallel; summary waits for both. Character image is an analogy, not workflow documentation. |

Each architecture slide keeps its original diagram on the left, with an image, caption and description on the right.
Validate offline: `python /workspaces/project/vibe-ops-ibm-tuke/tools/add_character_slides.py --check`.

## Earlier suggestions (not added)

Use two or three, not all six. Keep code and architecture slides readable;
use a short transition or an existing slide's spare space. Captions below are
ready to paste. Images in this section remain suggestions only.

| Placement | Template | Caption | Teaching point |
| --- | --- | --- | --- |
| After slide 13, “Everything is green. The login goes over HTTP.” | This Is Fine | “All health checks are green.” / “The login still uses HTTP.” | Availability is not security. Strongest opening joke. |
| After slide 15, certificate checks | Two Buttons | Buttons: “Fix certificate trust” / “Set verify=False”; person: “Me, five minutes before the demo” | Disabling verification hides the failure, not the risk. Never present this as a fix. |
| After slide 16, local-to-cloud pipeline | Drake Hotline Bling | Reject: “Upload raw traffic to the model” / Approve: “Keep captures local. Send sanitized findings.” | Evidence minimization is part of the design. |
| After slide 19 or 21, service / SDK distinctions | Spider-Man Pointing | Labels: “Strands: agent code” / “Bedrock: model API” / “AgentCore: runtime”; caption: “Different jobs. Similar names at 3 AM.” | Framework, inference and hosting are not interchangeable. |
| After slide 31, architecture comparison | Expanding Brain | “One agent” / “Agents calling agents” / “A graph of specialists” / “Start single. Add complexity only when evaluation proves value.” | More coordination is not automatically better. Strongest closing joke. |
| Before summary | The Office — handshake | Left: “ZAP detects”; middle: “Agents interpret”; right: “Humans approve and fix” | AI supports triage; it does not get automatic production authority. |

Recommended set: This Is Fine, Drake, Expanding Brain.
Use synthetic examples only; never put real credentials or captured traffic into a meme.

## Slide 33 — What we learned

- **Green is not secure.** Uptime checks can pass while a login uses HTTP.
- **Same loop, new evidence.** Signals, correlation, hypothesis, then a human-approved next step.
- **Keep sensitive data local.** ZAP detects locally; only allowlisted numeric scan summaries go to AWS.
- **Separate the jobs.** Strands coordinates agents, Bedrock serves the model, AgentCore runs the code.
- **Start single; validate every report.** Add specialists when evaluation shows value. Check schema and citations; humans approve and apply fixes.

Takeaway: **Better evidence, bounded agents, human control.**

## Slide 34 — Quick quiz: what would you do?

1. **All health checks pass. Is the login secure?**
   A: Yes, uptime proves it. · B: No, transport security needs separate evidence.
2. **What leaves the local lab in this demo?**
   A: Raw HAR and credentials. · B: Allowlisted numeric ZAP scan summaries.
3. **Which strategy requires both configured specialist reviews?**
   A: single · B: orchestrator · C: graph
4. **Can Guardrails replace schema and citation checks?**
   A: Yes · B: No

Presenter answers (also in quiz speaker notes): **1 B · 2 B · 3 C · 4 B**.
Ask for a one-sentence reason, not only a letter.
Bonus discussion: Who approves and applies the proposed fix? **Humans.**