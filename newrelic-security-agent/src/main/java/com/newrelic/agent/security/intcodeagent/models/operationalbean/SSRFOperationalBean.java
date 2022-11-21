package com.newrelic.agent.security.intcodeagent.models.operationalbean;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

public class SSRFOperationalBean extends AbstractOperationalBean {

    private String arg = StringUtils.EMPTY;

    private boolean isJNDILookup = false;

    public SSRFOperationalBean(String apiCallArg, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.arg = apiCallArg;
    }

    public SSRFOperationalBean(String apiCallArg, String className, String sourceMethod, String executionId, long startTime, String methodName, boolean isJNDILookup) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.arg = apiCallArg;
        this.isJNDILookup = isJNDILookup;
    }

    public boolean isJNDILookup() {
        return isJNDILookup;
    }

    public void setJNDILookup(boolean JNDILookup) {
        isJNDILookup = JNDILookup;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    @Override
    public boolean isEmpty() {
        return StringUtils.isBlank(this.arg);
    }

    public String getArg() {
        return arg;
    }

    public void setArg(String arg) {
        this.arg = arg;
    }
}

