
package com.newrelic.api.agent.security.schema.policy;

public class ApiBlocking {

    private Boolean enabled = false;
    private Boolean protectAllApis = false;
    private Boolean protectKnownVulnerableApis = false;
    private Boolean protectAttackedApis = false;

    /**
     * No args constructor for use in serialization
     */
    public ApiBlocking() {
    }

    /**
     * @param protectAllApis
     * @param protectKnownVulnerableApis
     * @param enabled
     * @param protectAttackedApis
     */
    public ApiBlocking(Boolean enabled, Boolean protectAllApis, Boolean protectKnownVulnerableApis, Boolean protectAttackedApis) {
        super();
        this.enabled = enabled;
        this.protectAllApis = protectAllApis;
        this.protectKnownVulnerableApis = protectKnownVulnerableApis;
        this.protectAttackedApis = protectAttackedApis;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean getProtectAllApis() {
        return protectAllApis;
    }

    public void setProtectAllApis(Boolean protectAllApis) {
        this.protectAllApis = protectAllApis;
    }

    public Boolean getProtectKnownVulnerableApis() {
        return protectKnownVulnerableApis;
    }

    public void setProtectKnownVulnerableApis(Boolean protectKnownVulnerableApis) {
        this.protectKnownVulnerableApis = protectKnownVulnerableApis;
    }

    public Boolean getProtectAttackedApis() {
        return protectAttackedApis;
    }

    public void setProtectAttackedApis(Boolean protectAttackedApis) {
        this.protectAttackedApis = protectAttackedApis;
    }
}
