package com.k2cybersecurity.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "allowedIps",
        "blockedIps"
})
public class AgentPolicyIPBlockingParameters {

    @JsonProperty("allowedIps")
    private List<String> allowedIps = new ArrayList<>();
    @JsonProperty("blockedIps")
    private List<String> blockedIps = new ArrayList<>();
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
    public AgentPolicyIPBlockingParameters(List<String> allowedIps, List<String> blockedIps) {
        super();
        this.allowedIps = allowedIps;
        this.blockedIps = blockedIps;
    }

    @JsonProperty("allowedIps")
    public List<String> getAllowedIps() {
        return allowedIps;
    }

    @JsonProperty("allowedIps")
    public void setAllowedIps(List<String> allowedIps) {
        this.allowedIps = allowedIps;
    }

    @JsonProperty("blockedIps")
    public List<String> getBlockedIps() {
        return blockedIps;
    }

    @JsonProperty("blockedIps")
    public void setBlockedIps(List<String> blockedIps) {
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

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}