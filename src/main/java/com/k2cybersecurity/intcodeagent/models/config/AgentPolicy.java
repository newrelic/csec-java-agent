
package com.k2cybersecurity.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "version",
        "logLevel",
        "policyPull",
        "policyPullInterval",
        "applicationInfo",
        "vulnerabilityScan",
        "protectionMode",
        "sendCompleteStackTrace",
        "enableHTTPRequestPrinting"
})
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentPolicy {

    @JsonProperty("version")
    private String version;
    @JsonProperty("lastUpdateTimestamp")
    private Long lastUpdateTimestamp;
    @JsonProperty("logLevel")
    private String logLevel;
    @JsonProperty("policyPull")
    private Boolean policyPull;
    @JsonProperty("policyPullInterval")
    private Integer policyPullInterval;
    @JsonProperty("applicationInfo")
    private PolicyApplicationInfo applicationInfo;
    @JsonProperty("vulnerabilityScan")
    private VulnerabilityScan vulnerabilityScan = new VulnerabilityScan();
    @JsonProperty("protectionMode")
    private ProtectionMode protectionMode = new ProtectionMode();
    //    @JsonProperty("policyParameters")
//    private AgentPolicyParameters policyParameters;
    @JsonProperty("sendCompleteStackTrace")
    private Boolean sendCompleteStackTrace;
    @JsonProperty("enableHTTPRequestPrinting")
    private Boolean enableHTTPRequestPrinting;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public AgentPolicy() {
    }

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


    @JsonProperty("version")
    public String getVersion() {
        return version;
    }

    @JsonProperty("version")
    public void setVersion(String version) {
        this.version = version;
    }

    @JsonProperty("lastUpdateTimestamp")
    public Long getLastUpdateTimestamp() {
        return lastUpdateTimestamp;
    }

    @JsonProperty("lastUpdateTimestamp")
    public void setLastUpdateTimestamp(Long lastUpdateTimestamp) {
        this.lastUpdateTimestamp = lastUpdateTimestamp;
    }

    @JsonProperty("logLevel")
    public String getLogLevel() {
        return logLevel;
    }

    @JsonProperty("logLevel")
    public void setLogLevel(String logLevel) {
        this.logLevel = logLevel;
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

    @JsonProperty("vulnerabilityScan")
    public VulnerabilityScan getVulnerabilityScan() {
        return vulnerabilityScan;
    }

    @JsonProperty("vulnerabilityScan")
    public void setVulnerabilityScan(VulnerabilityScan vulnerabilityScan) {
        this.vulnerabilityScan = vulnerabilityScan;
    }

    @JsonProperty("protectionMode")
    public ProtectionMode getProtectionMode() {
        return protectionMode;
    }

    @JsonProperty("protectionMode")
    public void setProtectionMode(ProtectionMode protectionMode) {
        this.protectionMode = protectionMode;
    }

    @JsonProperty("sendCompleteStackTrace")
    public Boolean getSendCompleteStackTrace() {
        return sendCompleteStackTrace;
    }

    @JsonProperty("sendCompleteStackTrace")
    public void setSendCompleteStackTrace(Boolean sendCompleteStackTrace) {
        this.sendCompleteStackTrace = sendCompleteStackTrace;
    }

    @JsonProperty("enableHTTPRequestPrinting")
    public Boolean getEnableHTTPRequestPrinting() {
        return enableHTTPRequestPrinting;
    }

    @JsonProperty("enableHTTPRequestPrinting")
    public void setEnableHTTPRequestPrinting(Boolean enableHTTPRequestPrinting) {
        this.enableHTTPRequestPrinting = enableHTTPRequestPrinting;
    }

    @JsonProperty("applicationInfo")
    public PolicyApplicationInfo getApplicationInfo() {
        return applicationInfo;
    }

    @JsonProperty("applicationInfo")
    public void setApplicationInfo(PolicyApplicationInfo applicationInfo) {
        this.applicationInfo = applicationInfo;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}
