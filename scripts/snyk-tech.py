#!/usr/bin/env python3
import os
import glob
import argparse

print("Detecting project tech stack for Snyk...")

# ------------------------
# Parse argument --path
# ------------------------
parser = argparse.ArgumentParser(description="Tech stack detector")
parser.add_argument("--path", default=".", help="Root folder to scan for project files")
args = parser.parse_args()

root = args.path
print(f"Scanning directory: {root}")

def exists(file):
    return os.path.exists(os.path.join(root, file))

def glob_in_root(pattern):
    return glob.glob(os.path.join(root, pattern))

stack = "unknown"

# ------------------------
# Tech stack detection
# ------------------------
if exists("pom.xml"):
    print("Detected Maven project")
    stack = "java-maven"

elif exists("build.gradle") or exists("build.gradle.kts"):
    print("Detected Gradle project")
    stack = "java-gradle"

elif exists("package.json"):
    print("Detected Node.js project")
    stack = "nodejs"

elif exists("angular.json"):
    print("Detected Angular project")
    stack = "angular"

elif glob_in_root("*.py") or exists("requirements.txt") or exists("pyproject.toml"):
    print("Detected Python project")
    stack = "python"

elif exists("app/src/main/AndroidManifest.xml"):
    print("Detected Android project")
    stack = "android"

elif glob_in_root("*.xcodeproj") or exists("Podfile"):
    print("Detected iOS (Swift/ObjC) project")
    stack = "ios"

elif exists("Dockerfile"):
    print("Detected Docker project")
    stack = "docker"

print(f"Detected Stack: {stack}")

# ------------------------
# Export variable for GitHub Actions
# ------------------------
github_env = os.getenv("GITHUB_ENV")
if github_env:
    with open(github_env, "a") as env_file:
        env_file.write(f"SNYK_STACK={stack}\n")
else:
    print("GITHUB_ENV not found")
