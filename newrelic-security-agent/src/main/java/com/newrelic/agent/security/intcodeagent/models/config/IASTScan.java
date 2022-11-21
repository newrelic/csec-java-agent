
package com.newrelic.agent.security.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "enabled",
        "probing"
})
public class IASTScan {

    @JsonProperty("enabled")
    private Boolean enabled = false;
    @JsonProperty("probing")
    private Probing probing = new Probing();
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public IASTScan() {
    }

    /**
     * @param enabled
     */
    public IASTScan(Boolean enabled) {
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

    @JsonProperty("probing")
    public Probing getProbing() {
        return probing;
    }

    @JsonProperty("probing")
    public void setProbing(Probing probing) {
        this.probing = probing;
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
