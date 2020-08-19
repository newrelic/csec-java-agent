
package com.k2cybersecurity.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "iastMode",
        "protectionMode"
})
public class AgentPolicy {

    @JsonProperty("iastMode")
    private IastMode iastMode = new IastMode();
    @JsonProperty("protectionMode")
    private ProtectionMode protectionMode = new ProtectionMode();
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public AgentPolicy() {
    }

    /**
     * @param iastMode
     * @param protectionMode
     */
    public AgentPolicy(IastMode iastMode, ProtectionMode protectionMode) {
        super();
        this.iastMode = iastMode;
        this.protectionMode = protectionMode;
    }

    @JsonProperty("iastMode")
    public IastMode getIastMode() {
        return iastMode;
    }

    @JsonProperty("iastMode")
    public void setIastMode(IastMode iastMode) {
        this.iastMode = iastMode;
    }

    @JsonProperty("protectionMode")
    public ProtectionMode getProtectionMode() {
        return protectionMode;
    }

    @JsonProperty("protectionMode")
    public void setProtectionMode(ProtectionMode protectionMode) {
        this.protectionMode = protectionMode;
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
