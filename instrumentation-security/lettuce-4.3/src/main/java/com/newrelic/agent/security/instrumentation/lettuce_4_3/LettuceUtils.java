package com.newrelic.agent.security.instrumentation.lettuce_4_3;

public class LettuceUtils {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "REDIS_OPERATION_LOCK_LETTUCE-";

    public static final String NR_SEC_CUSTOM_ATTR_FILTER_NAME = "REDIS_FILTER-";
    public static final String METHOD_DISPATCH = "dispatch";
    public static final String LETTUCE_4_3 = "LETTUCE-4.3";

    public static String getNrSecCustomAttribName(int hashCode) {
        return NR_SEC_CUSTOM_ATTR_FILTER_NAME + hashCode;
    }
}
