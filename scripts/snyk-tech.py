#!/usr/bin/env python3
import os

raw_stacks = os.getenv("SNYK_STACKS", "").strip()

print("🔍 Resolving Snyk commands for detected stacks...")

if not raw_stacks:
    print("⚠️  No stacks provided in SNYK_STACKS. Using default 'snyk test'.")
    stacks = []
else:
    stacks = [s.strip() for s in raw_stacks.split(",") if s.strip()]

print(f"📦 Parsed stacks: {stacks}")

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
commands = []

for stack in stacks:
    cmd = SNYK_COMMAND_MAP.get(stack)
    if not cmd:
        print(f"⚠️  Unknown stack '{stack}', using default: {DEFAULT_CMD}")
        cmd = DEFAULT_CMD
    commands.append(cmd)

print(f"✅ Resolved commands: {commands}")

# Write to GITHUB_ENV
github_env = os.getenv("GITHUB_ENV")
if github_env:
    with open(github_env, "a") as f:
        f.write(f"SNYK_CMDS={','.join(commands)}\n")
        f.write(f"SNYK_STACK_COUNT={len(stacks)}\n")
    print("💾 Exported SNYK_CMDS and SNYK_STACK_COUNT to GitHub environment.")
else:
    print("❌ GITHUB_ENV not found — unable to export commands.")
