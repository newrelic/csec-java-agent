package com.newrelic.agent.security.intcodeagent.models.collectorconfig;

import com.fasterxml.jackson.annotation.*;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
public class CustomerInfo {

    private String apiAccessorToken;

    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    public CustomerInfo() {
    }

    public String getApiAccessorToken() {
        return apiAccessorToken;
    }

    public void setApiAccessorToken(String apiAccessorToken) {
        this.apiAccessorToken = apiAccessorToken;
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
        CustomerInfo that = (CustomerInfo) o;
        return Objects.equals(apiAccessorToken, that.apiAccessorToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(apiAccessorToken);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public boolean isEmpty() {
        return StringUtils.isBlank(apiAccessorToken);
    }
}
