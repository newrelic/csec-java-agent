# Releasing csec-java-agent

Step-by-step guide for release of csec-java-agent, plus what the GitHub Actions
workflows do at each stage. csec-java-agent is published as a dependency consumed by
`newrelic-java-agent` - releasing it does not produce a
standalone runnable artifact.

## 1. Pre-release

1. Confirm you're releasing off `main` - every publish workflow below builds from the pushed/
   tagged ref, so a stray branch produces a stray artifact.
2. Bump CSEC version 
- `agentVersion` in `gradle.properties` (root of this repo).
- Also update `securityAgentVersion` in `newrelic-java-agent/gradle.properties` (in k2-JavaAgent).
3. Update `Changelog.md` (Keep a Changelog format - see existing entries for style).
4. Open/merge the version-bump + changelog PR to `main` like any other change. This PR triggers
   the same CI gates as any PR (section 2) plus, once merged, a snapshot publish (section 3).

## 2. CI gates (run automatically on every PR and push to `main`)

| Check | Workflow | What it does |
|---|---|---|
| Unit tests | `X-Reusable-Build-Security-Agent.yml` -> `.github/actions/unit-test` | Run unit tests and retries up to 4 times on failure before the job is marked failed. |
| CVE / dependency check | `dependency-submission.yml` | On every PR to `main`: submits the Gradle dependency graph (`newrelic-security-agent`/`newrelic-security-api` projects), then runs `actions/dependency-review-action` with `fail-on-severity: low` - **any newly-introduced CVE at low severity or above fails the PR check.** |
| Instrumentation verification | `verify-instrumentation.yml` -> `X-Reusable-VerifyInstrumentation.yml` | Not PR-gated - runs nightly (`cron: '0 0 * * *'`) against `main`, or on demand (`workflow_dispatch`/`workflow_call`). Reads every module under `instrumentation-security/` from `settings.gradle`, splits them across a paged matrix (GHA's 255-job matrix limit), and runs `:instrumentation:<module>:verifyInstrumentation` on **Java 17** for each. A Slack alert (`SLACK_WEBHOOK_URL_INST_VERIFIER`) fires on failure. |
## 3. Snapshot publish (automatic, no action needed)

Every push to `main` runs `publish-main-snapshot-to-maven.yml`, which calls the reusable
`publish-to-maven.yml` with `is-release=false`, `csec-run-unittest=true`,
`csec-run-instrumentation-verify=true`. Unit tests and instrumentation verification must pass
before it publishes `newrelic-security-api` and the CSEC agent to the Maven **snapshot**
repository via `./gradlew publish`.

Use this to sanity-check that a change resolves correctly as a dependency before cutting an
actual release.

## 4. Cut the release

1. Create a GitHub release (tag + release notes) from `main` in the csec-java-agent repo.
2. Publishing the release (`release: published`) triggers `publish-release-to-maven.yml`, which
   calls `publish-to-maven.yml` with `is-release=true`, `csec-run-unittest=false`,
   `csec-run-instrumentation-verify=false` (these already passed pre-merge/on `main`, so the
   release run skips re-running them).
## 5. Post-release verification

- [ ] Confirm the Central Sonatype upload step in `publish-release-to-maven.yml` returned 200 -
      visit https://central.sonatype.com/publishing/deployments to see the artifacts land.
- [ ] A silent Sonatype/GPG auth failure is the most likely release-day surprise - if the publish
      step succeeded but the upload step failed, the artifacts are staged but not released; you
      can re-run just the upload once credentials are fixed.
- [ ] Verify the Slack notification's `security-version`/`apm-version` match what you intended to
      release.
- [ ] From K2io repo `newrelic-java-agent` bump the CSEC Version, raise a PR on newrelic's repo `newrelic-java-agent`
## Required secrets

| Secret | Used for |
|---|---|
| `SONATYPE_USERNAME` / `SONATYPE_PASSWORD` | Maven Central / Sonatype auth (publish + staging upload) |
| `SIGNING_KEY` / `SIGNING_KEY_ID` / `SIGNING_KEY_PASSWORD` | GPG-signing published artifacts |
| `APM_AWS_ACCESS_KEY_ID` / `APM_AWS_SECRET_ACCESS_KEY` | Pulling the proprietary instrumentation jar zip from S3 during setup  |

## References

- `.github/workflows/dependency-submission.yml`
- `.github/workflows/verify-instrumentation.yml`, `X-Reusable-VerifyInstrumentation.yml`, `verify-instrumentation-single.yml`
- `.github/workflows/publish-main-snapshot-to-maven.yml`
- `.github/workflows/publish-release-to-maven.yml`
- `.github/workflows/publish-to-maven.yml`
- `.github/workflows/build-integrated-jar.yml`
- `.github/workflows/X-Reusable-Build-Security-Agent.yml`
- `.github/actions/unit-test/action.yml`, `setup-environment/action.yml`, `publish-csec-local/action.yml`
- `Changelog.md`, `gradle.properties`
- [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md) - building and running the agent locally
