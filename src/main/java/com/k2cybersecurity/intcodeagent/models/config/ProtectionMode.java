
package com.k2cybersecurity.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "enabled",
        "ipBlocking",
        "apiBlocking"
})
public class ProtectionMode {

    @JsonProperty("enabled")
    private Boolean enabled;
    @JsonProperty("ipBlocking")
    private IpBlocking ipBlocking = new IpBlocking();
    @JsonProperty("apiBlocking")
    private ApiBlocking apiBlocking = new ApiBlocking();
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public ProtectionMode() {
    }

    /**
     * @param ipBlocking
     * @param apiBlocking
     * @param enabled
     */
    public ProtectionMode(Boolean enabled, IpBlocking ipBlocking, ApiBlocking apiBlocking) {
        super();
        this.enabled = enabled;
        this.ipBlocking = ipBlocking;
        this.apiBlocking = apiBlocking;
    }

    @JsonProperty("enabled")
    public Boolean getEnabled() {
        return enabled;
    }

    @JsonProperty("enabled")
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    @JsonProperty("ipBlocking")
    public IpBlocking getIpBlocking() {
        return ipBlocking;
    }

    @JsonProperty("ipBlocking")
    public void setIpBlocking(IpBlocking ipBlocking) {
        this.ipBlocking = ipBlocking;
    }

    @JsonProperty("apiBlocking")
    public ApiBlocking getApiBlocking() {
        return apiBlocking;
    }

    @JsonProperty("apiBlocking")
    public void setApiBlocking(ApiBlocking apiBlocking) {
        this.apiBlocking = apiBlocking;
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
