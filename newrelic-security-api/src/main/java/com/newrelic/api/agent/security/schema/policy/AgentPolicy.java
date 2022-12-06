
package com.newrelic.api.agent.security.schema.policy;

public class AgentPolicy {

    private String version = "DEFAULT";
    private Long lastUpdateTimestamp = 0L;
    private Boolean policyPull = true;
    private Integer policyPullInterval = 60;
    private VulnerabilityScan vulnerabilityScan = new VulnerabilityScan();
    private ProtectionMode protectionMode = new ProtectionMode();
    private Boolean sendCompleteStackTrace = false;
    private Boolean enableHTTPRequestPrinting = false;

    public AgentPolicy() {}

    /**
     * @param vulnerabilityScan
     * @param protectionMode
     */
    public AgentPolicy(VulnerabilityScan vulnerabilityScan, ProtectionMode protectionMode) {
        this();
        this.vulnerabilityScan = vulnerabilityScan;
        this.protectionMode = protectionMode;
        this.sendCompleteStackTrace = false;
    }


    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Long getLastUpdateTimestamp() {
        return lastUpdateTimestamp;
    }

    public void setLastUpdateTimestamp(Long lastUpdateTimestamp) {
        this.lastUpdateTimestamp = lastUpdateTimestamp;
    }

    public Boolean getPolicyPull() {
        return policyPull;
    }

    public void setPolicyPull(Boolean policyPull) {
        this.policyPull = policyPull;
    }

    public Integer getPolicyPullInterval() {
        return policyPullInterval;
    }

    public void setPolicyPullInterval(Integer policyPullInterval) {
        this.policyPullInterval = policyPullInterval;
    }

    public VulnerabilityScan getVulnerabilityScan() {
        return vulnerabilityScan;
    }

    public void setVulnerabilityScan(VulnerabilityScan vulnerabilityScan) {
        this.vulnerabilityScan = vulnerabilityScan;
    }

    public ProtectionMode getProtectionMode() {
        return protectionMode;
    }

    public void setProtectionMode(ProtectionMode protectionMode) {
        this.protectionMode = protectionMode;
    }

    public Boolean getSendCompleteStackTrace() {
        return sendCompleteStackTrace;
    }

    public void setSendCompleteStackTrace(Boolean sendCompleteStackTrace) {
        this.sendCompleteStackTrace = sendCompleteStackTrace;
    }

    public Boolean getEnableHTTPRequestPrinting() {
        return enableHTTPRequestPrinting;
    }

    public void setEnableHTTPRequestPrinting(Boolean enableHTTPRequestPrinting) {
        this.enableHTTPRequestPrinting = enableHTTPRequestPrinting;
    }
}
