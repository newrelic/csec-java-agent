package com.newrelic.api.agent.security.schema.policy;

import java.util.ArrayList;
import java.util.List;

public class RestrictionCriteria {

    private ScanTime scanTime = new ScanTime();

    private AccountInfo accountInfo = new AccountInfo();

    private List<MappingParameters> mappingParameters = new ArrayList<>();

    private SkipScanParameters skipScanParameters  = new SkipScanParameters();

    private List<StrictMappings> strictMappings = new ArrayList<>();

    public RestrictionCriteria() {
    }

    public ScanTime getScanTime() {
        return scanTime;
    }

    public void setScanTime(ScanTime scanTime) {
        this.scanTime = scanTime;
    }

    public AccountInfo getAccountInfo() {
        return accountInfo;
    }

    public void setAccountInfo(AccountInfo accountInfo) {
        this.accountInfo = accountInfo;
    }

    public List<MappingParameters> getMappingParameters() {
        return mappingParameters;
    }

    public void setMappingParameters(List<MappingParameters> mappingParameters) {
        this.mappingParameters = mappingParameters;
    }

    public SkipScanParameters getSkipScanParameters() {
        return skipScanParameters;
    }

    public void setSkipScanParameters(SkipScanParameters skipScanParameters) {
        this.skipScanParameters = skipScanParameters;
    }

    public List<StrictMappings> getStrictMappings() {
        return strictMappings;
    }

    public void setStrictMappings(List<StrictMappings> strictMappings) {
        this.strictMappings = strictMappings;
    }
}
