package com.nr.agent.instrumentation.security.okhttp30.internal;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import okhttp3.Request;

public class OkhttpHelper {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "OKHTTP_OPERATION_LOCK-";

    public static final String METHOD_EXECUTE = "execute";

    public static boolean skipExistsEvent() {
        if (!(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled() &&
                NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled())) {
            return true;
        }

        return false;
    }

    public static boolean isLockAcquired() {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getNrSecCustomAttribName(), Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean acquireLockIfPossible() {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isLockAcquired()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    public static void releaseLock() {
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), null);
            }
        } catch (Throwable ignored) {
        }
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static AbstractOperation preprocessSecurityHook(String url, String className, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    url == null || url.trim().isEmpty()) {
                return null;
            }

            SSRFOperation operation = new SSRFOperation(url,
                    className, methodName);
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || OkhttpHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }

    public static Request addSecurityHeaders(Request.Builder requestBuilder, AbstractOperation operation) {
        if (operation == null || requestBuilder == null) {
            return null;
        }

        // Add Security IAST header
        String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
        if (iastHeader != null && !iastHeader.trim().isEmpty()) {
            requestBuilder.addHeader(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
        }

        if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
            // Add Security distributed tracing header
            requestBuilder.removeHeader(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            requestBuilder.addHeader(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER,
                    SSRFUtils.generateTracingHeaderValue(NewRelicSecurity.getAgent().getSecurityMetaData()
                                    .getTracingHeaderValue(),
                            operation.getApiID(), operation.getExecutionId(),
                            NewRelicSecurity.getAgent().getAgentUUID()));
        }
        return requestBuilder.build();
    }
}
