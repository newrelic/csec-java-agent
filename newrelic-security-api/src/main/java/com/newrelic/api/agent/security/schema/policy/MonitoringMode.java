package com.newrelic.api.agent.security.schema.policy;

import java.util.concurrent.atomic.AtomicBoolean;

public class MonitoringMode {

    private int harvestCycle = 60; //in seconds

    private int maxHarvestsPerCycle = 60;

    private AtomicBoolean harvesting = new AtomicBoolean(false);

    private int max_event_quota = 100;

    public int getHarvestCycle() {
        return harvestCycle;
    }

    public void setHarvestCycle(int harvestCycle) {
        this.harvestCycle = harvestCycle;
    }

    public int getMaxHarvestsPerCycle() {
        return maxHarvestsPerCycle;
    }

    public void setMaxHarvestsPerCycle(int maxHarvestsPerCycle) {
        this.maxHarvestsPerCycle = maxHarvestsPerCycle;
    }

    public AtomicBoolean getHarvesting() {
        return harvesting;
    }

    public void setHarvesting(AtomicBoolean harvesting) {
        this.harvesting = harvesting;
    }

    public int getMax_event_quota() {
        return max_event_quota;
    }

    public void setMax_event_quota(int max_event_quota) {
        this.max_event_quota = max_event_quota;
    }
}
