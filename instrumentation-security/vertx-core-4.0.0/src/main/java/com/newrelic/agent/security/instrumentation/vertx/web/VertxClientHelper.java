package com.newrelic.agent.security.instrumentation.vertx.web;

import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class VertxClientHelper {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "VERTX_WEB_OPERATION_LOCK-";

    public static final String METHOD_END = "end";

    public static final String VERTX_WEB_4_0_0 = "Vertx-Web-4.0.0";

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
