package com.newrelic.api.agent.security.schema;

import java.util.Arrays;

public class DeserialisationContext {

    private String entityName;

    private StackTraceElement[] stacktrace;

    public DeserialisationContext(String entityName, StackTraceElement[] stacktrace) {
        this.entityName = entityName;
        this.stacktrace = stacktrace;
    }

    public DeserialisationContext(DeserialisationContext deserialisationContext) {
        this.entityName = deserialisationContext.getEntityName();
        this.stacktrace = Arrays.copyOf(deserialisationContext.getStacktrace(), deserialisationContext.getStacktrace().length);
    }

    public String getEntityName() {
        return entityName;
    }

    public void setEntityName(String entityName) {
        this.entityName = entityName;
    }

    public StackTraceElement[] getStacktrace() {
        return stacktrace;
    }

    public void setStacktrace(StackTraceElement[] stacktrace) {
        this.stacktrace = stacktrace;
    }
}
