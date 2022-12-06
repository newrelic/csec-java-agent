package com.newrelic.api.agent.security.schema;

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
