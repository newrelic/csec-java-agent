
package com.k2cybersecurity.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "enabled"
})
public class CVEScan {

    @JsonProperty("enabled")
    private Boolean enabled = false;
    @JsonProperty("enableEnvScan")
    private Boolean enableEnvScan = true;
    @JsonProperty("cveDefinitionUpdateInterval")
    private Integer cveDefinitionUpdateInterval = 360;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public CVEScan() {
    }

    /**
     * @param enabled
     */
    public CVEScan(Boolean enabled) {
        super();
        this.enabled = enabled;
    }

    @JsonProperty("enabled")
    public Boolean getEnabled() {
        return enabled;
    }

    @JsonProperty("enabled")
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    @JsonProperty("enableEnvScan")
    public Boolean getEnableEnvScan() {
        return enableEnvScan;
    }

    @JsonProperty("enableEnvScan")
    public void setEnableEnvScan(Boolean enableEnvScan) {
        this.enableEnvScan = enableEnvScan;
    }

    @JsonProperty("cveDefinitionUpdateInterval")
    public Integer getCveDefinitionUpdateInterval() {
        return cveDefinitionUpdateInterval;
    }

    @JsonProperty("cveDefinitionUpdateInterval")
    public void setCveDefinitionUpdateInterval(Integer cveDefinitionUpdateInterval) {
        this.cveDefinitionUpdateInterval = cveDefinitionUpdateInterval;
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
