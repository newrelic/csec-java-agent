package com.newrelic.agent.security.instrumentation.org.asynchttpclient;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.asynchttpclient.Request;

public class AsynchttpHelper {


    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "ASYNCHTTP_OPERATION_LOCK-";

    public static final String METHOD_EXECUTE = "executeRequest";
    public static final String ASYNC_HTTP_CLIENT_2_0_0 = "ASYNC_HTTP_CLIENT_2.0.0";

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
                NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, ASYNC_HTTP_CLIENT_2_0_0, e.getMessage()), e, AsynchttpHelper.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, ASYNC_HTTP_CLIENT_2_0_0, e.getMessage()), e, AsynchttpHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, ASYNC_HTTP_CLIENT_2_0_0, e.getMessage()), e, AsynchttpHelper.class.getName());
        }
        return null;
    }

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, AsynchttpHelper.ASYNC_HTTP_CLIENT_2_0_0, ignored.getMessage()), ignored, AsynchttpHelper.class.getName());
        }
    }

    public static Request addSecurityHeaders(Request request, AbstractOperation operation) {
        if (operation == null || request == null) {
            return null;
        }

        // Add Security IAST header
        String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
        if (iastHeader != null && !iastHeader.trim().isEmpty()) {
            request.getHeaders().add(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
        }

        String csecParaentId = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
        if(StringUtils.isNotBlank(csecParaentId)){
            request.getHeaders().add(GenericHelper.CSEC_PARENT_ID, csecParaentId);
        }

        if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
            // Add Security distributed tracing header
            request.getHeaders().remove(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            request.getHeaders().add(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER,
                    SSRFUtils.generateTracingHeaderValue(NewRelicSecurity.getAgent().getSecurityMetaData()
                                    .getTracingHeaderValue(),
                            operation.getApiID(), operation.getExecutionId(),
                            NewRelicSecurity.getAgent().getAgentUUID()));
        }
        return request;
    }
}
