
package com.newrelic.agent.security.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "enabled",
        "protectAllApis",
        "protectKnownVulnerableApis",
        "protectAttackedApis"
})
public class ApiBlocking {

    @JsonProperty("enabled")
    private Boolean enabled = false;
    @JsonProperty("protectAllApis")
    private Boolean protectAllApis = false;
    @JsonProperty("protectKnownVulnerableApis")
    private Boolean protectKnownVulnerableApis = false;
    @JsonProperty("protectAttackedApis")
    private Boolean protectAttackedApis = false;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public ApiBlocking() {
    }

    /**
     * @param protectAllApis
     * @param protectKnownVulnerableApis
     * @param enabled
     * @param protectAttackedApis
     */
    public ApiBlocking(Boolean enabled, Boolean protectAllApis, Boolean protectKnownVulnerableApis, Boolean protectAttackedApis) {
        super();
        this.enabled = enabled;
        this.protectAllApis = protectAllApis;
        this.protectKnownVulnerableApis = protectKnownVulnerableApis;
        this.protectAttackedApis = protectAttackedApis;
    }

    @JsonProperty("enabled")
    public Boolean getEnabled() {
        return enabled;
    }

    @JsonProperty("enabled")
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    @JsonProperty("protectAllApis")
    public Boolean getProtectAllApis() {
        return protectAllApis;
    }

    @JsonProperty("protectAllApis")
    public void setProtectAllApis(Boolean protectAllApis) {
        this.protectAllApis = protectAllApis;
    }

    @JsonProperty("protectKnownVulnerableApis")
    public Boolean getProtectKnownVulnerableApis() {
        return protectKnownVulnerableApis;
    }

    @JsonProperty("protectKnownVulnerableApis")
    public void setProtectKnownVulnerableApis(Boolean protectKnownVulnerableApis) {
        this.protectKnownVulnerableApis = protectKnownVulnerableApis;
    }

    @JsonProperty("protectAttackedApis")
    public Boolean getProtectAttackedApis() {
        return protectAttackedApis;
    }

    @JsonProperty("protectAttackedApis")
    public void setProtectAttackedApis(Boolean protectAttackedApis) {
        this.protectAttackedApis = protectAttackedApis;
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
