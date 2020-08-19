
package com.k2cybersecurity.intcodeagent.models.config;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "enabled",
        "staticScanning",
        "dynamicScanning",
        "enableHooks"
})
public class IastMode {

    @JsonProperty("enabled")
    private Boolean enabled = false;
    @JsonProperty("staticScanning")
    private StaticScanning staticScanning = new StaticScanning();
    @JsonProperty("dynamicScanning")
    private DynamicScanning dynamicScanning = new DynamicScanning();
    @JsonProperty("enableHooks")
    private Boolean enableHooks = false;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * No args constructor for use in serialization
     */
    public IastMode() {
    }

    /**
     * @param enableHooks
     * @param staticScanning
     * @param enabled
     * @param dynamicScanning
     */
    public IastMode(Boolean enabled, StaticScanning staticScanning, DynamicScanning dynamicScanning, Boolean enableHooks) {
        super();
        this.enabled = enabled;
        this.staticScanning = staticScanning;
        this.dynamicScanning = dynamicScanning;
        this.enableHooks = enableHooks;
    }

    @JsonProperty("enabled")
    public Boolean getEnabled() {
        return enabled;
    }

    @JsonProperty("enabled")
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    @JsonProperty("staticScanning")
    public StaticScanning getStaticScanning() {
        return staticScanning;
    }

    @JsonProperty("staticScanning")
    public void setStaticScanning(StaticScanning staticScanning) {
        this.staticScanning = staticScanning;
    }

    @JsonProperty("dynamicScanning")
    public DynamicScanning getDynamicScanning() {
        return dynamicScanning;
    }

    @JsonProperty("dynamicScanning")
    public void setDynamicScanning(DynamicScanning dynamicScanning) {
        this.dynamicScanning = dynamicScanning;
    }

    @JsonProperty("enableHooks")
    public Boolean getEnableHooks() {
        return enableHooks;
    }

    @JsonProperty("enableHooks")
    public void setEnableHooks(Boolean enableHooks) {
        this.enableHooks = enableHooks;
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
