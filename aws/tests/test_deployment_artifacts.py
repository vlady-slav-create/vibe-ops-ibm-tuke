"""After packaging: python -m tests.test_deployment_artifacts from AWS directory."""
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile


def main():
    root = Path(__file__).resolve().parents[1]
    with TemporaryDirectory() as directory:
        target = Path(directory)
        with ZipFile(root / "build/lambda_functions.zip") as archive:
            names = archive.namelist()
            assert all(f"lambda_functions/{task}.py" in names for task in ("start_analysis", "analyze_and_store", "publish_findings"))
            assert "lambda_functions/templates/finding.json.mustache" in names
            assert "contracts/security_report.py" in names
            assert "contracts/normalize.jq" in names
            assert "contracts/schemas.json" in names
            assert "lambda_functions/scan_context.py" in names
            assert not any(name.startswith(("agentcore_runtime/", "tests/", "pip/")) for name in names)
            archive.extractall(target)
        subprocess.run([sys.executable, "-S", "-c",
                        "from lambda_functions.start_analysis import handler; "
                        "from lambda_functions.analyze_and_store import handler as analyze_handler; "
                        "from lambda_functions.publish_findings import handler as publish_handler; "
                        "from lambda_functions.security_hub import render; "
                        "from contracts.schema import validate_schema; "
                        "from contracts.evidence import normalize, validate; "
                        "event = normalize({'source': 'network-capture', 'event': 'tls_client_rejected', "
                        "'captured_at': '2026-11-14T00:00:00Z'}); "
                        "assert validate({'mode': 'single', 'events': [event]}) == [event]; "
                        "validate_schema('report', {'summary': 'Review', 'work_items': []}); "
                        "validate_schema('resultKeys', ['results/graph/' + 'a' * 64 + '.json']); "
                        "assert all(callable(f) for f in (handler, analyze_handler, publish_handler)); "
                        "assert render('remediation.mustache', {'fix': 'Review', 'retest': 'Recapture'}) "
                        "== 'Fix: Review\\nAcceptance/retest: Recapture'"], cwd=target, check=True)
    with TemporaryDirectory() as directory:
        target = Path(directory)
        for name in ("agentcore_runtime", "contracts"):
            shutil.copytree(root / name, target / name, ignore=shutil.ignore_patterns("__pycache__"))
        subprocess.run([sys.executable, "-c",
                        "from agentcore_runtime.http_server import Handler, analyze; "
                        "from contracts.schema import validate_schema; "
                        "from contracts.evidence import normalize; "
                        "assert normalize({'source': 'network-capture', 'event': 'tls_client_rejected', "
                        "'captured_at': '2026-11-14T00:00:00Z'})['event_id']; "
                        "from agentcore_runtime.bedrock_analysis import load_skill; "
                        "assert load_skill('application-security-review').instructions; "
                        "assert load_skill('evidence-quality-review').instructions; "
                        "validate_schema('report', {'summary': 'Review', 'work_items': []}); "
                        "assert callable(analyze)"], cwd=target, check=True)
    print("PASS: isolated Lambda artifact imports/templates and AgentCore source imports")


if __name__ == "__main__":
    main()