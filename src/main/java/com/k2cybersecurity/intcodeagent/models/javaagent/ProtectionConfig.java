package com.k2cybersecurity.intcodeagent.models.javaagent;

public class ProtectionConfig {
    private Boolean generateEventResponse = false;
    private Boolean protectKnownVulnerableAPIs = false;
    private Boolean autoAddDetectedVulnerabilitiesToProtectionList = false;
    private Boolean autoAttackIPBlockingXFF = false;

    private static ProtectionConfig instance;

    private static final Object mutex = new Object();

    private ProtectionConfig(){}

    public static ProtectionConfig getInstance() {
        synchronized (mutex){
            if(instance == null) {
                instance = new ProtectionConfig();
            }
        }
        return instance;
    }

    public static void setInstance(ProtectionConfig protectionConfig){
        ProtectionConfig.getInstance().setAutoAddDetectedVulnerabilitiesToProtectionList(protectionConfig.autoAddDetectedVulnerabilitiesToProtectionList);
        ProtectionConfig.getInstance().setGenerateEventResponse(protectionConfig.generateEventResponse);
        ProtectionConfig.getInstance().setProtectKnownVulnerableAPIs(protectionConfig.protectKnownVulnerableAPIs);
        ProtectionConfig.getInstance().setAutoAttackIPBlockingXFF(protectionConfig.autoAttackIPBlockingXFF);
    }

    public Boolean getGenerateEventResponse() {
        return generateEventResponse;
    }

    public void setGenerateEventResponse(Boolean generateEventResponse) {
        this.generateEventResponse = generateEventResponse;
    }

    public Boolean getProtectKnownVulnerableAPIs() {
        return protectKnownVulnerableAPIs;
    }

    public void setProtectKnownVulnerableAPIs(Boolean protectKnownVulnerableAPIs) {
        this.protectKnownVulnerableAPIs = protectKnownVulnerableAPIs;
    }

    public Boolean getAutoAddDetectedVulnerabilitiesToProtectionList() {
        return autoAddDetectedVulnerabilitiesToProtectionList;
    }

    public void setAutoAddDetectedVulnerabilitiesToProtectionList(Boolean autoAddDetectedVulnerabilitiesToProtectionList) {
        this.autoAddDetectedVulnerabilitiesToProtectionList = autoAddDetectedVulnerabilitiesToProtectionList;
    }

    public Boolean getAutoAttackIPBlockingXFF() {
        return autoAttackIPBlockingXFF;
    }

    public void setAutoAttackIPBlockingXFF(Boolean autoAttackIPBlockingXFF) {
        this.autoAttackIPBlockingXFF = autoAttackIPBlockingXFF;
    }
}
