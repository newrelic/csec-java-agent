package com.newrelic.agent.security.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "url",
        "vulnerabilityCaseType",
        "impactingPayloadKeys"
})
public class BlockedRequest {

    @JsonProperty("url")
    private String url;

    @JsonProperty("vulnerabilityCaseType")
    private VulnerabilityCaseType vulnerabilityCaseType;

    @JsonProperty("impactingPayloadKeys")
    private Set<String> impactingPayloadKeys;

    @JsonProperty("url")
    public String getUrl() {
        return url;
    }

    @JsonProperty("url")
    public void setUrl(String url) {
        this.url = url;
    }

    @JsonProperty("vulnerabilityCaseType")
    public VulnerabilityCaseType getVulnerabilityCaseType() {
        return vulnerabilityCaseType;
    }

    @JsonProperty("vulnerabilityCaseType")
    public void setVulnerabilityCaseType(VulnerabilityCaseType vulnerabilityCaseType) {
        this.vulnerabilityCaseType = vulnerabilityCaseType;
    }

    @JsonProperty("impactingPayloadKeys")
    public Set<String> getImpactingPayloadKeys() {
        return impactingPayloadKeys;
    }

    @JsonProperty("impactingPayloadKeys")
    public void setImpactingPayloadKeys(Set<String> impactingPayloadKeys) {
        this.impactingPayloadKeys = impactingPayloadKeys;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
