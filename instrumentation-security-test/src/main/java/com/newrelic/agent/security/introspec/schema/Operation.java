package com.newrelic.agent.security.introspec.schema;

import com.newrelic.api.agent.security.schema.operation.ForkExecOperation;

import java.util.Map;

public class Operation extends ForkExecOperation {
    public Operation(String cmd, Map<String, String> environment, String className, String methodName) {
        super(cmd, environment, className, methodName);
    }
}
