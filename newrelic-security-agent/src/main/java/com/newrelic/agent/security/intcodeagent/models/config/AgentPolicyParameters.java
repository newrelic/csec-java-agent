package com.newrelic.agent.security.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "version",
        "timestamp",
        "lastUpdateTimestamp",
        "policyPullInterval",
        "attackerIpTimeout",
        "allowedIps",
        "blockedIps",
        "allowedApis",
        "blockedApis",
        "allowedRequests"
})
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentPolicyParameters {

    @JsonProperty("version")
    private String version;

    @JsonProperty("timestamp")
    private Long timestamp;

    @JsonProperty("lastUpdateTimestamp")
    private Long lastUpdateTimestamp;

    //In minutes
    @JsonProperty("attackerIpTimeout")
    private Integer attackerIpTimeout;

    @JsonProperty("policyPullInterval")
    private Integer policyPullInterval;

    @JsonProperty("allowedIps")
    private Set<String> allowedIps = new HashSet<>();
    @JsonProperty("blockedIps")
    private Set<String> blockedIps = new HashSet<>();

    @JsonProperty("allowedApis")
    private Set<String> allowedApis = new HashSet<>();
    @JsonProperty("blockedApis")
    private Set<String> blockedApis = new HashSet<>();

    @JsonProperty("allowedRequests")
    private Set<BlockedRequest> allowedRequests = new HashSet<>();

    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public AgentPolicyParameters() {
        this.version = "0";
    }

    /**
     * @param allowedIps
     * @param blockedIps
     */
    public AgentPolicyParameters(Set<String> allowedIps, Set<String> blockedIps) {
        super();
        this.allowedIps = allowedIps;
        this.blockedIps = blockedIps;
    }

    @JsonProperty("version")
    public String getVersion() {
        return version;
    }

    @JsonProperty("version")
    public void setVersion(String version) {
        this.version = version;
    }

    @JsonProperty("policyPullInterval")
    public Integer getPolicyPullInterval() {
        return policyPullInterval;
    }

    @JsonProperty("policyPullInterval")
    public void setPolicyPullInterval(Integer policyPullInterval) {
        this.policyPullInterval = policyPullInterval;
    }

    @JsonProperty("allowedIps")
    public Set<String> getAllowedIps() {
        return allowedIps;
    }

    @JsonProperty("allowedIps")
    public void setAllowedIps(Set<String> allowedIps) {
        this.allowedIps = allowedIps;
    }

    @JsonProperty("blockedIps")
    public Set<String> getBlockedIps() {
        return blockedIps;
    }

    @JsonProperty("blockedIps")
    public void setBlockedIps(Set<String> blockedIps) {
        this.blockedIps = blockedIps;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    @JsonProperty("allowedApis")
    public Set<String> getAllowedApis() {
        return allowedApis;
    }

    @JsonProperty("allowedApis")
    public void setAllowedApis(Set<String> allowedApis) {
        this.allowedApis = allowedApis;
    }

    @JsonProperty("blockedApis")
    public Set<String> getBlockedApis() {
        return blockedApis;
    }

    @JsonProperty("blockedApis")
    public void setBlockedApis(Set<String> blockedApis) {
        this.blockedApis = blockedApis;
    }

    @JsonProperty("allowedRequests")
    public Set<BlockedRequest> getAllowedRequests() {
        return allowedRequests;
    }

    @JsonProperty("allowedRequests")
    public void setAllowedRequests(Set<BlockedRequest> allowedRequests) {
        this.allowedRequests = allowedRequests;
    }

    public void setAdditionalProperties(Map<String, Object> additionalProperties) {
        this.additionalProperties = additionalProperties;
    }

    @JsonProperty("timestamp")
    public Long getTimestamp() {
        return timestamp;
    }

    @JsonProperty("timestamp")
    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    @JsonProperty("lastUpdateTimestamp")
    public Long getLastUpdateTimestamp() {
        return lastUpdateTimestamp;
    }

    @JsonProperty("lastUpdateTimestamp")
    public void setLastUpdateTimestamp(Long lastUpdateTimestamp) {
        this.lastUpdateTimestamp = lastUpdateTimestamp;
    }

    @JsonProperty("attackerIpTimeout")
    public Integer getAttackerIpTimeout() {
        return attackerIpTimeout;
    }

    @JsonProperty("attackerIpTimeout")
    public void setAttackerIpTimeout(Integer attackerIpTimeout) {
        this.attackerIpTimeout = attackerIpTimeout;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}