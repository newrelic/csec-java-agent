package com.newrelic.agent.security.schema;

public class UserClassEntity {
    private boolean isCalledByUserCode;
    private StackTraceElement userClassElement;
    private int traceLocationStart = -1;
    private int traceLocationEnd = -1;

    public UserClassEntity() {
    }

    public boolean isCalledByUserCode() {
        return isCalledByUserCode;
    }

    public void setCalledByUserCode(boolean calledByUserCode) {
        isCalledByUserCode = calledByUserCode;
    }

    public StackTraceElement getUserClassElement() {
        return userClassElement;
    }

    public void setUserClassElement(StackTraceElement userClassElement) {
        this.userClassElement = userClassElement;
    }

    public int getTraceLocationStart() {
        return traceLocationStart;
    }

    public void setTraceLocationStart(int traceLocationStart) {
        this.traceLocationStart = traceLocationStart;
    }

    public int getTraceLocationEnd() {
        return traceLocationEnd;
    }

    public void setTraceLocationEnd(int traceLocationEnd) {
        this.traceLocationEnd = traceLocationEnd;
    }
}
