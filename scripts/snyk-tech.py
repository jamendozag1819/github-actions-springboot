#!/usr/bin/env python3
import os
import glob
import json

print("🔎 Detecting project tech stack...")

detected = []

def exists(path):
    return os.path.exists(path)

# --------------------------
# Java (Maven / Gradle)
# --------------------------
if exists("pom.xml"):
    print("✔ Detected: Java (Maven)")
    detected.append("java-maven")

if exists("build.gradle") or exists("build.gradle.kts"):
    print("✔ Detected: Java (Gradle)")
    detected.append("java-gradle")

# --------------------------
# Node.js
# --------------------------
if exists("package.json"):
    print("✔ Detected: Node.js")
    detected.append("nodejs")

# --------------------------
# Angular
# --------------------------
if exists("angular.json"):
    print("✔ Detected: Angular")
    detected.append("angular")

# --------------------------
# Python
# --------------------------
if glob.glob("*.py") or exists("requirements.txt") or exists("pyproject.toml"):
    print("✔ Detected: Python")
    detected.append("python")

# --------------------------
# Android
# --------------------------
if exists("app/src/main/AndroidManifest.xml"):
    print("✔ Detected: Android")
    detected.append("android")

# --------------------------
# iOS / Swift / ObjC
# --------------------------
if glob.glob("*.xcodeproj") or exists("Podfile"):
    print("✔ Detected: iOS (Swift/ObjC)")
    detected.append("ios")

# --------------------------
# Docker
# --------------------------
if exists("Dockerfile"):
    print("✔ Detected: Docker")
    detected.append("docker")

# --------------------------
# Fallback
# --------------------------
if not detected:
    detected = ["unknown"]
    print("⚠ No known tech detected. Marked as: unknown")

# Convert list to JSON string
json_output = json.dumps(detected)
print(f"\n📦 Detected stack list: {json_output}")

# ----------------------------------------
# Export to GitHub Actions outputs
# ----------------------------------------
github_env = os.getenv("GITHUB_ENV")
github_output = os.getenv("GITHUB_OUTPUT")

if github_env:
    with open(github_env, "a") as env_file:
        env_file.write(f"SNYK_STACKS={json_output}\n")

if github_output:
    with open(github_output, "a") as out_file:
        out_file.write(f"stacks={json_output}\n")

print("✅ Export complete")
