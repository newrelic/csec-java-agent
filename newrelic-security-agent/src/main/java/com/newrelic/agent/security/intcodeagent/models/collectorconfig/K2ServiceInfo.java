package com.newrelic.agent.security.intcodeagent.models.collectorconfig;

import com.fasterxml.jackson.annotation.*;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
public class K2ServiceInfo {

    private String validatorServiceEndpointURL;

    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    public String getValidatorServiceEndpointURL() {
        return validatorServiceEndpointURL;
    }

    public void setValidatorServiceEndpointURL(String validatorServiceEndpointURL) {
        this.validatorServiceEndpointURL = validatorServiceEndpointURL;
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
        K2ServiceInfo that = (K2ServiceInfo) o;
        return validatorServiceEndpointURL.equals(that.validatorServiceEndpointURL);
    }

    @Override
    public int hashCode() {
        return Objects.hash(validatorServiceEndpointURL);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public boolean isEmpty() {
        return StringUtils.isAnyBlank(validatorServiceEndpointURL);
    }
}
