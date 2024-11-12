
package com.newrelic.api.agent.security.schema.policy;

import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;

public class IASTScan {

    private Boolean enabled = true;
    private Probing probing = new Probing();
    private Boolean restricted = false;
    private Boolean monitoring = false;
    private RestrictionCriteria restrictionCriteria = new RestrictionCriteria();
    private MonitoringMode monitoringMode = new MonitoringMode();

    /**
     * No args constructor for use in serialization
     */
    public IASTScan() {
    }

    /**
     * @param enabled
     */
    public IASTScan(Boolean enabled) {
        super();
        this.enabled = enabled;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Probing getProbing() {
        return probing;
    }

    public void setProbing(Probing probing) {
        this.probing = probing;
    }

    public Boolean getRestricted() {
        return restricted;
    }

    public void setRestricted(Boolean restricted) {
        this.restricted = restricted;
    }

    public RestrictionCriteria getRestrictionCriteria() {
        return restrictionCriteria;
    }

    public void setRestrictionCriteria(RestrictionCriteria restrictionCriteria) {
        this.restrictionCriteria = restrictionCriteria;
    }

    public Boolean getMonitoring() {
        return monitoring;
    }

    public void setMonitoring(Boolean monitoring) {
        this.monitoring = monitoring;
    }

    public MonitoringMode getMonitoringMode() {
        return monitoringMode;
    }

    public void setMonitoringMode(MonitoringMode monitoringMode) {
        this.monitoringMode = monitoringMode;
    }
}
