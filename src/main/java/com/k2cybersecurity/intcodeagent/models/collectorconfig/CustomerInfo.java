package com.k2cybersecurity.intcodeagent.models.collectorconfig;

import com.fasterxml.jackson.annotation.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
public class CustomerInfo {

    private Integer customerId;

    private String apiAccessorToken;

    private String emailId;

    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    public CustomerInfo() {
    }

    public Integer getCustomerId() {
        return customerId;
    }

    public void setCustomerId(Integer customerId) {
        this.customerId = customerId;
    }

    public String getApiAccessorToken() {
        return apiAccessorToken;
    }

    public void setApiAccessorToken(String apiAccessorToken) {
        this.apiAccessorToken = apiAccessorToken;
    }

    public String getEmailId() {
        return emailId;
    }

    public void setEmailId(String emailId) {
        this.emailId = emailId;
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
        return Objects.equals(customerId, that.customerId) &&
                Objects.equals(apiAccessorToken, that.apiAccessorToken) &&
                Objects.equals(emailId, that.emailId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(customerId, apiAccessorToken, emailId);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public boolean isEmpty() {
        return StringUtils.isBlank(apiAccessorToken) || customerId == null;
    }
}
