
package com.newrelic.agent.security.schema.policy;

public class IpBlocking {

    private Boolean enabled = false;
    private Boolean attackerIpBlocking = false;
    private Boolean ipDetectViaXFF = false;

    /**
     * No args constructor for use in serialization
     */
    public IpBlocking() {
    }

    /**
     * @param attackerIpBlocking
     * @param ipDetectViaXFF
     * @param enabled
     */
    public IpBlocking(Boolean enabled, Boolean attackerIpBlocking, Boolean ipDetectViaXFF) {
        super();
        this.enabled = enabled;
        this.attackerIpBlocking = attackerIpBlocking;
        this.ipDetectViaXFF = ipDetectViaXFF;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean getAttackerIpBlocking() {
        return attackerIpBlocking;
    }

    public void setAttackerIpBlocking(Boolean attackerIpBlocking) {
        this.attackerIpBlocking = attackerIpBlocking;
    }

    public Boolean getIpDetectViaXFF() {
        return ipDetectViaXFF;
    }

    public void setIpDetectViaXFF(Boolean ipDetectViaXFF) {
        this.ipDetectViaXFF = ipDetectViaXFF;
    }

}
