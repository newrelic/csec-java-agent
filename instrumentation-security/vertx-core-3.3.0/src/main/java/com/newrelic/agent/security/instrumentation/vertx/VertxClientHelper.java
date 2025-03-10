package com.newrelic.agent.security.instrumentation.vertx;

import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class VertxClientHelper {
    private static final String NR_SEC_CUSTOM_ATTRIB_NAME = "VERTX_CORE_OPERATION_LOCK-";
    public static final String METHOD_END = "end";

    public static final String VERTX_CORE_3_3_0 = "VERTX-CORE-3.3.0";
    private static String getNrSecCustomAttribName() {
        return VertxClientHelper.NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }
    public static void releaseLock() {
        GenericHelper.releaseLock(getNrSecCustomAttribName());
    }

    public static boolean acquireLockIfPossible(VulnerabilityCaseType httpRequest) {
        return GenericHelper.acquireLockIfPossible(httpRequest, getNrSecCustomAttribName());
    }
}
