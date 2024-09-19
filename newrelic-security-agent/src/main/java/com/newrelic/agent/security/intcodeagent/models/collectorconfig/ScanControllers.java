package com.newrelic.agent.security.intcodeagent.models.collectorconfig;

public class ScanControllers {

    private String iastTestIdentifier;

    private Integer scanInstanceCount = 0;

    public ScanControllers() {
    }

    public String getIastTestIdentifier() {
        return iastTestIdentifier;
    }

    public void setIastTestIdentifier(String iastTestIdentifier) {
        this.iastTestIdentifier = iastTestIdentifier;
    }

    public Integer getScanInstanceCount() {
        return scanInstanceCount;
    }

    public void setScanInstanceCount(Integer scanInstanceCount) {
        this.scanInstanceCount = scanInstanceCount;
    }
}
