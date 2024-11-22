package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.intcodeagent.models.javaagent.ApplicationRuntimeError;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RuntimeErrorReporter {

    Map<Integer, ApplicationRuntimeError> errors = new ConcurrentHashMap<>();

    private RuntimeErrorReporter() {
    }

    private static final class InstanceHolder {
        static final RuntimeErrorReporter instance = new RuntimeErrorReporter();
    }

    public static RuntimeErrorReporter getInstance() {
        return InstanceHolder.instance;
    }

    public boolean addApplicationRuntimeError(ApplicationRuntimeError error) {
        if(errors.containsKey(error.hashCode())) {
            errors.get(error.hashCode()).incrementCounter();
        } else {
            errors.put(error.hashCode(), error);
        }
        return true;
    }

    public void clearErrors() {
        errors.clear();
    }

    public void reportApplicationRuntimeError() {
        for (ApplicationRuntimeError applicationRuntimeError : errors.values()) {
            EventSendPool.getInstance().sendEvent(applicationRuntimeError, "postApplicationRuntimeError");
        }
        errors.clear();
    }
}
