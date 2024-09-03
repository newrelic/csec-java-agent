package com.newrelic.api.agent.security.schema.policy;

import com.newrelic.api.agent.security.schema.annotations.JsonProperty;

public class MappingParameters {

    @JsonProperty("account_id_location")
    private HttpParameterLocation accountIdLocation;

    @JsonProperty("account_id_key")
    private String accountIdKey;

    public MappingParameters() {
    }

    public MappingParameters(HttpParameterLocation accountIdLocation) {
        this.accountIdLocation = accountIdLocation;
    }

    public MappingParameters(HttpParameterLocation accountIdLocation, String accountIdKey) {
        this.accountIdLocation = accountIdLocation;
        this.accountIdKey = accountIdKey;
    }

    public HttpParameterLocation getAccountIdLocation() {
        return accountIdLocation;
    }

    public void setAccountIdLocation(HttpParameterLocation accountIdLocation) {
        this.accountIdLocation = accountIdLocation;
    }

    public String getAccountIdKey() {
        return accountIdKey;
    }

    public void setAccountIdKey(String accountIdKey) {
        this.accountIdKey = accountIdKey;
    }
}
