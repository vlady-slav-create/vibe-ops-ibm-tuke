"""Start Compose with restricted STS credentials resolved from deployment outputs."""
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[2]
    os.chdir(root)
    outputs = json.loads(subprocess.check_output(
        ["terraform", "-chdir=aws/terraform", "output", "-json"], text=True))
    role, region, stream = [outputs[key]["value"] for key in
                            ("publisher_role_arn", "region", "stream_name")]
    if not all(isinstance(value, str) and value for value in (role, region, stream)):
        raise ValueError("Missing deployment outputs; run make terraform-apply first")
    response = json.loads(subprocess.check_output(
        ["aws", "sts", "assume-role", "--role-arn", role,
         "--role-session-name", "sniff-lab-publisher", "--duration-seconds", "3600",
         "--region", region, "--output", "json", "--no-cli-pager"], text=True))
    credentials = response["Credentials"]
    env = dict(os.environ, AWS_REGION=region, KINESIS_STREAM_NAME=stream)
    for key, field in (("AWS_ACCESS_KEY_ID", "AccessKeyId"),
                       ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"),
                       ("AWS_SESSION_TOKEN", "SessionToken")):
        value = credentials[field]
        if not isinstance(value, str) or not value:
            raise ValueError("STS returned incomplete credentials")
        env[key] = value
    # Publisher uses resolved credentials, not the host's profile name.
    for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SECURITY_TOKEN"):
        env.pop(key, None)
    subprocess.run(["docker", "compose", "up", "-d", "--build"], env=env, check=True)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, TypeError, ValueError):
        sys.exit("Invalid deployment outputs or STS response; apply Terraform and check host AWS login.")
    except (OSError, subprocess.CalledProcessError):
        sys.exit("Compose startup failed; check command error above. No credentials were written to files.")