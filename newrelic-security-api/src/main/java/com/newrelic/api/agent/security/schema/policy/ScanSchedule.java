package com.newrelic.api.agent.security.schema.policy;

import java.util.Date;

public class ScanSchedule {

    private int duration = -1;

    private String schedule;

    private Date nextScanTime;

    private int delay = 0;

    public ScanSchedule() {
    }

    public int getDuration() {
        return duration;
    }

    public void setDuration(int duration) {
        this.duration = duration;
    }

    public String getSchedule() {
        return schedule;
    }

    public void setSchedule(String schedule) {
        this.schedule = schedule;
    }

    public Date getNextScanTime() {
        return nextScanTime;
    }

    public void setNextScanTime(Date nextScanTime) {
        this.nextScanTime = nextScanTime;
    }

    public int getDelay() {
        return delay;
    }

    public void setDelay(int delay) {
        this.delay = delay;
    }
}
