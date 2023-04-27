package com.newrelic.api.agent.security.schema;

public class UserClassEntity {
    private boolean isCalledByUserCode;
    private StackTraceElement userClassElement;

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

}
