#!/usr/bin/env python3
import os
import json

stack = os.getenv("SNYK_STACK", "unknown")

print(f"Resolving Snyk command for stack: {stack}")

SNYK_COMMAND_MAP = {
    "java-maven": "snyk test --all-projects",
    "java-gradle": "snyk test --all-projects",
    "android": "snyk test --all-projects",
    "ios": "snyk test --all-projects",
    "angular": "snyk test --all-projects",
    "nodejs": "snyk test",
    "python": "snyk test",
    "docker": "snyk container test"
}

DEFAULT_CMD = "snyk test"

command = SNYK_COMMAND_MAP.get(stack, DEFAULT_CMD)

print(f"Resolved command: {command}")

github_env = os.getenv("GITHUB_ENV")
if github_env:
    with open(github_env, "a") as f:
        f.write(f"SNYK_CMD={command}\n")
else:
    print("GITHUB_ENV not found")
