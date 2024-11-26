package com.newrelic.api.agent.security.schema.policy;

import java.util.concurrent.atomic.AtomicBoolean;

public class MonitoringMode {

    private int harvestCycle = 60; //in seconds

    private int maxHarvestsPerCycle = 60;

    private AtomicBoolean harvesting = new AtomicBoolean(false);

    private int maxEventQuota = 100;

    private int eventQuotaTimeDuration = 360; //in minutes

    private int repeat = 0; //0 means keep repeating

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

    public int getMaxEventQuota() {
        return maxEventQuota;
    }

    public void setMaxEventQuota(int maxEventQuota) {
        this.maxEventQuota = maxEventQuota;
    }

    public int getEventQuotaTimeDuration() {
        return eventQuotaTimeDuration;
    }

    public void setEventQuotaTimeDuration(int eventQuotaTimeDuration) {
        this.eventQuotaTimeDuration = eventQuotaTimeDuration;
    }

    public int getRepeat() {
        return repeat;
    }

    public void setRepeat(int repeat) {
        this.repeat = repeat;
    }
}
