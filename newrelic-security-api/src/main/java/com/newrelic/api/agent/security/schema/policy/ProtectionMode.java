
package com.newrelic.api.agent.security.schema.policy;

public class ProtectionMode {

    private Boolean enabled = false;
    private IpBlocking ipBlocking = new IpBlocking();
    private ApiBlocking apiBlocking = new ApiBlocking();

    /**
     * No args constructor for use in serialization
     */
    public ProtectionMode() {
    }

    /**
     * @param ipBlocking
     * @param apiBlocking
     * @param enabled
     */
    public ProtectionMode(Boolean enabled, IpBlocking ipBlocking, ApiBlocking apiBlocking) {
        super();
        this.enabled = enabled;
        this.ipBlocking = ipBlocking;
        this.apiBlocking = apiBlocking;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public IpBlocking getIpBlocking() {
        return ipBlocking;
    }

    public void setIpBlocking(IpBlocking ipBlocking) {
        this.ipBlocking = ipBlocking;
    }

    public ApiBlocking getApiBlocking() {
        return apiBlocking;
    }

    public void setApiBlocking(ApiBlocking apiBlocking) {
        this.apiBlocking = apiBlocking;
    }

}
