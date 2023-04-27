package com.newrelic.agent.security.intcodeagent.models.javaagent;

public enum APIRecordStatus {

    INSERTED("INSERTED"),

    PROCESSED("PROCESSED"),

    PRESCANNED("PRESCANNED"),

    SAFE("SAFE"),

    VULNERABLE("VULNERABLE");

    private final String status;

    private APIRecordStatus(String status) {
        this.status = status;
    }

    /**
     * @return the status
     */
    public String getStatus() {
        return status;
    }

}
