package com.newrelic.agent.security.instrumentation.lettuce_6_0;

public class LettuceUtils {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "REDIS_OPERATION_LOCK_LETTUCE-";

    public static final String NR_SEC_CUSTOM_ATTR_FILTER_NAME = "REDIS_FILTER-";
    public static final String METHOD_DISPATCH = "dispatch";

    public static String getNrSecCustomAttribName(int hashCode) {
        return NR_SEC_CUSTOM_ATTR_FILTER_NAME + hashCode;
    }
}
