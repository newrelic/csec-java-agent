
package com.newrelic.agent.security.schema.policy;

import com.newrelic.agent.security.schema.policy.ApiBlocking;
import com.newrelic.agent.security.schema.policy.IpBlocking;

public class ProtectionMode {

    private Boolean enabled = false;
    private com.newrelic.agent.security.schema.policy.IpBlocking ipBlocking = new com.newrelic.agent.security.schema.policy.IpBlocking();
    private com.newrelic.agent.security.schema.policy.ApiBlocking apiBlocking = new com.newrelic.agent.security.schema.policy.ApiBlocking();

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
    public ProtectionMode(Boolean enabled, com.newrelic.agent.security.schema.policy.IpBlocking ipBlocking, com.newrelic.agent.security.schema.policy.ApiBlocking apiBlocking) {
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

    public com.newrelic.agent.security.schema.policy.IpBlocking getIpBlocking() {
        return ipBlocking;
    }

    public void setIpBlocking(IpBlocking ipBlocking) {
        this.ipBlocking = ipBlocking;
    }

    public com.newrelic.agent.security.schema.policy.ApiBlocking getApiBlocking() {
        return apiBlocking;
    }

    public void setApiBlocking(ApiBlocking apiBlocking) {
        this.apiBlocking = apiBlocking;
    }

}
