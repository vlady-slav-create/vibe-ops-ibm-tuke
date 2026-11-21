"""Terraform apply hook: build and push a content-tagged ARM64 runtime image."""
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    context = Path(__file__).resolve().parents[1]
    repository = os.environ["ECR_REPOSITORY_URL"]
    tag = os.environ["IMAGE_TAG"]
    region = os.environ["AWS_REGION"]
    # Immutable tags can survive interrupted applies; reuse an already pushed image.
    existing = subprocess.run(
        ["aws", "ecr", "describe-images", "--repository-name", repository.split("/", 1)[1],
         "--image-ids", f"imageTag={tag}", "--region", region, "--no-cli-pager"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    if existing.returncode == 0:
        print("Runtime image already exists; reusing immutable tag", flush=True)
        return
    if "ImageNotFoundException" not in existing.stderr:
        raise RuntimeError(existing.stderr)
    password = subprocess.check_output(
        ["aws", "ecr", "get-login-password", "--region", region], text=True)
    # Keep registry credentials out of the user's persistent Docker config.
    with tempfile.TemporaryDirectory() as config:
        env = dict(os.environ, DOCKER_CONFIG=config)
        # Temp config hides the active docker context (Colima, OrbStack, Desktop); pin its socket.
        if "DOCKER_HOST" not in env:
            host = subprocess.run(
                ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                capture_output=True, text=True).stdout.strip()
            if host:
                env["DOCKER_HOST"] = host
        # Docker finds CLI plugins (buildx) under $DOCKER_CONFIG; expose the user's.
        plugins = Path(os.environ.get("DOCKER_CONFIG", Path.home() / ".docker")) / "cli-plugins"
        if plugins.is_dir():
            (Path(config) / "cli-plugins").symlink_to(plugins)
        subprocess.run(["docker", "login", "--username", "AWS", "--password-stdin",
                        repository.split("/", 1)[0]], input=password, text=True, env=env, check=True)
        subprocess.run(
            ["docker", "buildx", "build", "--platform", "linux/arm64", "--provenance=false",
             "-f", str(context / "agentcore_runtime/Dockerfile"),
             "-t", f"{repository}:{tag}", "--push", str(context)], env=env, check=True)


if __name__ == "__main__":
    main()