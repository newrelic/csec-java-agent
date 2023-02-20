package com.newrelic.agent.security.intcodeagent.properties;

import java.time.Clock;

public class BuildInfo {
    private String collectorVersion = "UNKNOWN";
    private String buildTime = Clock.systemUTC().instant().toString();
    private String commitId = "UNKNOWN";
    private String jsonVersion = "UNKNOWN";
    private String buildNumber = "UNKNOWN";

    public String getCollectorVersion() {
        return collectorVersion;
    }

    public void setCollectorVersion(String collectorVersion) {
        this.collectorVersion = collectorVersion;
    }

    public String getBuildTime() {
        return buildTime;
    }

    public void setBuildTime(String buildTime) {
        this.buildTime = buildTime;
    }

    public String getCommitId() {
        return commitId;
    }

    public void setCommitId(String commitId) {
        this.commitId = commitId;
    }

    public String getJsonVersion() {
        return jsonVersion;
    }

    public void setJsonVersion(String jsonVersion) {
        this.jsonVersion = jsonVersion;
    }

    public String getBuildNumber() {
        return buildNumber;
    }

    public void setBuildNumber(String buildNumber) {
        this.buildNumber = buildNumber;
    }
}
