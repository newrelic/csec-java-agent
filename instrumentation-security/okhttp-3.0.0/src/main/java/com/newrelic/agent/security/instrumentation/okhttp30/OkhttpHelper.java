package com.newrelic.agent.security.instrumentation.okhttp30;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import okhttp3.Request;

public class OkhttpHelper {

    private static final String NR_SEC_CUSTOM_ATTRIB_NAME = "OKHTTP_OPERATION_LOCK-";

    public static final String METHOD_EXECUTE = "execute";
    public static final String OKHTTP_3_0_0 = "OKHTTP-3.0.0";

    public static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static AbstractOperation preprocessSecurityHook(String url, String className, String methodName) {
        try {
            if (url == null || url.trim().isEmpty()) {
                return null;
            }

            SSRFOperation operation = new SSRFOperation(url,
                    className, methodName);
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, OKHTTP_3_0_0, e.getMessage()), e, OkhttpHelper.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, OKHTTP_3_0_0, e.getMessage()), e, OkhttpHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, OKHTTP_3_0_0, e.getMessage()), e, OkhttpHelper.class.getName());
        }
        return null;
    }

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExitEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, OKHTTP_3_0_0, e.getMessage()), e, OkhttpHelper.class.getName());
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

        String csecParaentId = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
        if(StringUtils.isNotBlank(csecParaentId)){
            requestBuilder.addHeader(GenericHelper.CSEC_PARENT_ID, csecParaentId);
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
