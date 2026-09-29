# Building and Running csec-java-agent Locally

This doc walks through building csec-java-agent agent end to end on a dev machine: the
base APM Java agent and the security agent.
## 1. Overview

`csec-java-agent` is built and published as a dependency for  use in `newrelic-java-agent` only - it is not a standalone artifact you run by itself.

It depends on artifacts published by a fork of the APM Java agent:

- Repo: `k2io/newrelic-java-agent` (a New Relic fork, org `k2io`)
- Branch to use: `csec-dev`
- Referred to informally below as **"K2-JavaAgent"**

## 2. Prerequisites

- Install java AdoptOpenJDK  8 and java versions 11 and 17 as well.
- **JDK 8 is required** to build both repos. Configure it in
  `~/.gradle/gradle.properties` file:
  ```properties
  jdk8=/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home
  ```
- Two repos checked out locally:
  1. `newrelic-java-agent` - https://github.com/k2io/newrelic-java-agent,
     checked out on branch `csec-dev`.
  2. `csec-java-agent` - https://github.com/newrelic/csec-java-agent.
- `./gradlew` works from each repo's own root.

## 3 - Build the Dependencies from APM Java Agent

All commands in this section run from the **`newrelic-java-agent` root**
(k2io fork, `csec-dev` branch).

### Step 1 - Publish prerequisite modules to Maven local

```bash
./gradlew clean \
  :newrelic-api:publishToMavenLocal \
  :agent-bridge:publishToMavenLocal \
  :agent-bridge-datastore:publishToMavenLocal \
  :newrelic-weaver-api:publishToMavenLocal \
  :newrelic-weaver:publishToMavenLocal \
  :newrelic-weaver-scala:publishToMavenLocal \
  :newrelic-weaver-scala-api:publishToMavenLocal \
  --parallel
```

## 4 - Build the CSEC Java Agent

All commands in this section run from the **`csec-java-agent` root**.
Publish API and agent locally.

### 4.1 - Build and publish the security API

```bash
./gradlew ${GRADLE_OPTIONS} :newrelic-security-api:publishToMavenLocal \
  --parallel
```

### 4.2 - Build and publish the security agent

```bash
./gradlew ${GRADLE_OPTIONS} publishToMavenLocal \
  --parallel
```

### Build the standalone security agent jar [OPTIONAL]

```bash
./gradlew clean jar --parallel
```

Artifacts land at:

```
newrelic-security-agent/build/libs
```

Only needed if you want the jar itself rather than just installing to Maven
local for `newrelic-java-agent` to pick up.
## References

- `csec-java-agent/README.md` - "Building" section (source for Part 2 baseline commands)
- `csec-java-agent/.github/actions/publish-csec-local/action.yml`
- `newrelic-java-agent/README.md` - "Building" section (source for Part 1 baseline commands)
- `newrelic-java-agent/.github/actions/setup-environment/action.yml` - `GRADLE_OPTIONS` definition
- [RELEASE.md](RELEASE.md) - build/package/publish steps and release CI workflows
