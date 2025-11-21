#!/usr/bin/env python3
import os
import glob

print("Detecting project tech stack...")

prop_files = ["sonar-prop-config/sonar-common.properties"]

def exists(path):
    return os.path.exists(path)

if exists("pom.xml"):
    print("Detected Maven project")
    prop_files.append("sonar-prop-config/sonar-maven.properties")

if exists("build.gradle") or exists("build.gradle.kts"):
    print("Detected Gradle project")
    prop_files.append("sonar-prop-config/sonar-gradle.properties")

if exists("package.json"):
    print("Detected Node.js project")
    prop_files.append("sonar-prop-config/sonar-node.properties")

if exists("angular.json"):
    print("Detected Angular project")
    prop_files.append("sonar-prop-config/sonar-angular.properties")

if glob.glob("*.py"):
    print("Detected Python project")
    prop_files.append("sonar-prop-config/sonar-python.properties")

if exists("app/src/main/AndroidManifest.xml"):
    print("Detected Android project")
    prop_files.append("sonar-prop-config/sonar-android.properties")

if glob.glob("*.xcodeproj"):
    print("Detected iOS (Swift/ObjC) project")
    prop_files.append("sonar-prop-config/sonar-ios.properties")

prop_string = ",".join(prop_files)

print(f"Using Sonar property files: {prop_string}")

github_env = os.getenv("GITHUB_ENV")
if github_env:
    with open(github_env, "a") as env_file:
        env_file.write(f"SONAR_PROPS={prop_string}\n")
else:
    print("GITHUB_ENV not found")
