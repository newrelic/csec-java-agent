package com.k2cybersecurity.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "allowedIps",
        "blockedIps",
        "allowedApis",
        "blockedApis"
})
public class AgentPolicyIPBlockingParameters {

    @JsonProperty("allowedIps")
    private Set<String> allowedIps = new HashSet<>();
    @JsonProperty("blockedIps")
    private Set<String> blockedIps = new HashSet<>();

    @JsonProperty("allowedApis")
    private Set<String> allowedApis = new HashSet<>();
    @JsonProperty("blockedApis")
    private Set<String> blockedApis = new HashSet<>();


    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public AgentPolicyIPBlockingParameters() {
    }

    /**
     * @param allowedIps
     * @param blockedIps
     */
    public AgentPolicyIPBlockingParameters(Set<String> allowedIps, Set<String> blockedIps) {
        super();
        this.allowedIps = allowedIps;
        this.blockedIps = blockedIps;
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

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}