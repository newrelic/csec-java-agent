package com.newrelic.agent.security.instrumentation.nashorn;

public class JSEngineUtils {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "JSENGINE_OPERATION_LOCK_NASHORN-";

    public static final String METHOD_EVAL_IMPL = "evalImpl";
    public static final String NASHORN_CONTENT = "NASHORN-CONTENT-";
    public static final String NASHORN_JS_INJECTION = "NASHORN-JS-INJECTION";
}
