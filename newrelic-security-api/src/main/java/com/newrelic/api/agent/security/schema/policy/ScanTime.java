package com.newrelic.api.agent.security.schema.policy;

import java.util.Date;

public class ScanTime {

    private int duration;

    private String schedule;

    private Date nextScanTime;

    public ScanTime() {
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
}
