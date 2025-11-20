#!/usr/bin/env python3
import os

stack = os.getenv("SNYK_STACK", "").strip()

print("🔍 Resolving Snyk command for single stack...")

if not stack:
    print("⚠️  No SNYK_STACK provided — using default 'snyk test'.")
    stack = "unknown"

print(f"📦 Stack: {stack}")

SNYK_COMMAND_MAP = {
    "java-maven": "snyk test --all-projects",
    "java-gradle": "snyk test --all-projects",
    "android": "snyk test --all-projects",
    "ios": "snyk test --all-projects",
    "angular": "snyk test --all-projects",
    "nodejs": "snyk test",
    "python": "snyk test",
    "docker": "snyk test --docker Dockerfile"
}

DEFAULT_CMD = "snyk test"
command = SNYK_COMMAND_MAP.get(stack)

if not command:
    print(f"⚠️  Unknown stack '{stack}', using default: {DEFAULT_CMD}")
    command = DEFAULT_CMD

print(f"✅ Resolved command: {command}")

# Write to GITHUB_ENV
github_env = os.getenv("GITHUB_ENV")
if github_env:
    with open(github_env, "a") as f:
        f.write(f"SNYK_CMD={command}\n")
    print("💾 Exported SNYK_CMD to GitHub environment.")
else:
    print("❌ GITHUB_ENV not found — unable to export command.")
