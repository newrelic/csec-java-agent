package com.k2cybersecurity.intcodeagent.models.collectorconfig;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.models.config.PolicyApplicationInfo;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
public class ApplicationLevelConfig {

    private CustomerInfo customerInfo;

    private K2ServiceInfo k2ServiceInfo;

    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    public ApplicationLevelConfig() {
    }

    public CustomerInfo getCustomerInfo() {
        return customerInfo;
    }

    public void setCustomerInfo(CustomerInfo customerInfo) {
        this.customerInfo = customerInfo;
    }

    public K2ServiceInfo getK2ServiceInfo() {
        return k2ServiceInfo;
    }

    public void setK2ServiceInfo(K2ServiceInfo k2ServiceInfo) {
        this.k2ServiceInfo = k2ServiceInfo;
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApplicationLevelConfig that = (ApplicationLevelConfig) o;
        return Objects.equals(customerInfo, that.customerInfo) &&
                Objects.equals(k2ServiceInfo, that.k2ServiceInfo);
    }

    @Override
    public int hashCode() {
        return Objects.hash(customerInfo, k2ServiceInfo);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
