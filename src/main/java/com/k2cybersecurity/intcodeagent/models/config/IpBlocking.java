
package com.k2cybersecurity.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "enabled",
        "attackerIpBlocking",
        "ipDetectViaXFF",
        "timeout",
        "parameterFilePath"
})
public class IpBlocking {

    @JsonProperty("enabled")
    private Boolean enabled;
    @JsonProperty("attackerIpBlocking")
    private Boolean attackerIpBlocking;
    @JsonProperty("ipDetectViaXFF")
    private Boolean ipDetectViaXFF;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public IpBlocking() {
    }

    /**
     * @param attackerIpBlocking
     * @param ipDetectViaXFF
     * @param enabled
     */
    public IpBlocking(Boolean enabled, Boolean attackerIpBlocking, Boolean ipDetectViaXFF) {
        super();
        this.enabled = enabled;
        this.attackerIpBlocking = attackerIpBlocking;
        this.ipDetectViaXFF = ipDetectViaXFF;
    }

    @JsonProperty("enabled")
    public Boolean getEnabled() {
        return enabled;
    }

    @JsonProperty("enabled")
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    @JsonProperty("attackerIpBlocking")
    public Boolean getAttackerIpBlocking() {
        return attackerIpBlocking;
    }

    @JsonProperty("attackerIpBlocking")
    public void setAttackerIpBlocking(Boolean attackerIpBlocking) {
        this.attackerIpBlocking = attackerIpBlocking;
    }

    @JsonProperty("ipDetectViaXFF")
    public Boolean getIpDetectViaXFF() {
        return ipDetectViaXFF;
    }

    @JsonProperty("ipDetectViaXFF")
    public void setIpDetectViaXFF(Boolean ipDetectViaXFF) {
        this.ipDetectViaXFF = ipDetectViaXFF;
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
