package com.newrelic.agent.security.instrumentation.ning.http_1_1;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.ning.http.client.Request;

public class NingHelper {
    public static final String METHOD_NAME_EXECUTE = "execute";
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SSRF_OPERATION_LOCK_NING-";

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }

    public static AbstractOperation preprocessSecurityHook(Request request, String uri, String methodName, String className) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            // Add Security IAST header
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                request.getHeaders().add(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
            }

            String csecParaentId = securityMetaData.getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
            if(StringUtils.isNotBlank(csecParaentId)){
                request.getHeaders().add(GenericHelper.CSEC_PARENT_ID, csecParaentId);
            }

            SSRFOperation operation = new SSRFOperation(uri, className, methodName);
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
                NewRelicSecurity.getAgent().registerOperation(operation);
            } finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    request.getHeaders().add(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID()));
                }
            }
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }

    public static void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
    }

    public static boolean acquireLockIfPossible(VulnerabilityCaseType httpRequest, int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(httpRequest, NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
        return false;
    }
}
