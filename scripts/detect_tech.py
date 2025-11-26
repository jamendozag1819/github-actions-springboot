#!/usr/bin/env python3
import os
import glob

print("Detecting project tech stack for Snyk...")

stack = "unknown"

def exists(path):
    return os.path.exists(path)

if exists("Dockerfile"):
    print("Detected Docker project")
    stack = "docker"
elif exists("pom.xml"):
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

elif glob.glob("*.py") or exists("requirements.txt") or exists("pyproject.toml"):
    print("Detected Python project")
    stack = "python"

elif exists("app/src/main/AndroidManifest.xml"):
    print("Detected Android project")
    stack = "android"

elif glob.glob("*.xcodeproj") or exists("Podfile"):
    print("Detected iOS (Swift/ObjC) project")
    stack = "ios"



print(f"Detected Stack: {stack}")

github_env = os.getenv("GITHUB_ENV")
if github_env:
    with open(github_env, "a") as env_file:
        env_file.write(f"SNYK_STACK={stack}\n")
else:
    print("GITHUB_ENV not found")
