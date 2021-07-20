package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

public class SSRFOperationalBean extends AbstractOperationalBean {

    private String arg = StringUtils.EMPTY;

    public SSRFOperationalBean(String apiCallArg, String className, String sourceMethod, String executionId, long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.arg = apiCallArg;
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

