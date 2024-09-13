package com.newrelic.api.agent.security.schema.policy;

import java.util.List;

public class MappingParameter {

    private boolean enabled;

    private List<String> locations;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getLocations() {
        return locations;
    }

    public void setLocations(List<String> locations) {
        this.locations = locations;
    }

    public MappingParameter() {
    }

    public MappingParameter(boolean enabled, List<String> locations) {
        this.enabled = enabled;
        this.locations = locations;
    }
}
