package com.newrelic.api.agent.security.schema.policy;

import java.util.ArrayList;
import java.util.List;

public class RestrictionCriteria {

    private AccountInfo accountInfo = new AccountInfo();

    private MappingParameters mappingParameters = new MappingParameters();

    private List<StrictMappings> strictMappings = new ArrayList<>();

    public RestrictionCriteria() {
    }

    public AccountInfo getAccountInfo() {
        return accountInfo;
    }

    public void setAccountInfo(AccountInfo accountInfo) {
        this.accountInfo = accountInfo;
    }

    public MappingParameters getMappingParameters() {
        return mappingParameters;
    }

    public void setMappingParameters(MappingParameters mappingParameters) {
        this.mappingParameters = mappingParameters;
    }

    public List<StrictMappings> getStrictMappings() {
        return strictMappings;
    }

    public void setStrictMappings(List<StrictMappings> strictMappings) {
        this.strictMappings = strictMappings;
    }
}
