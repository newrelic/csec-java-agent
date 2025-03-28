package com.newrelic.agent.security.instrumentation.grpc1220;

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
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import io.grpc.Metadata;

public class GrpcClientUtils {
    private static final String METHOD_NAME_START = "start";

    private static final String NR_SEC_CUSTOM_ATTRIB_NAME = "NR_CSEC_GRPC_CLIENT_OPERATIONAL_LOCK_";

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(
                    LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, GrpcUtils.GRPC_1_22_0, e.getMessage()), e, GrpcClientUtils.class.getName());
        }
    }

    public static AbstractOperation preprocessSecurityHook(String uri, Metadata meta, String klass) {
        try {
            SSRFOperation operation = new SSRFOperation(uri, klass, METHOD_NAME_START);

            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
            NewRelicSecurity.getAgent().registerOperation(operation);
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                meta.put(Metadata.Key.of(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, Metadata.ASCII_STRING_MARSHALLER), iastHeader);
            }
            if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() && operation.getExecutionId() != null &&
                    !operation.getExecutionId().trim().isEmpty()) {
                meta.put(Metadata.Key.of(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, Metadata.ASCII_STRING_MARSHALLER), SSRFUtils.generateTracingHeaderValue(NewRelicSecurity.getAgent().getSecurityMetaData().getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID()));
            }
            String csecParaentId = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
            if(StringUtils.isNotBlank(csecParaentId)){
                meta.put(Metadata.Key.of(GenericHelper.CSEC_PARENT_ID, Metadata.ASCII_STRING_MARSHALLER), csecParaentId);
            }
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, GrpcUtils.GRPC_1_22_0, e.getMessage()), e, GrpcClientUtils.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, GrpcUtils.GRPC_1_22_0, e.getMessage()), e, GrpcClientUtils.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, GrpcUtils.GRPC_1_22_0, e.getMessage()), e, GrpcClientUtils.class.getName());
        }
        return null;
    }


    public static void releaseLock() {
        GenericHelper.releaseLock(getNrSecCustomAttrName());
    }

    private static String getNrSecCustomAttrName() {
        return GrpcClientUtils.NR_SEC_CUSTOM_ATTRIB_NAME+Thread.currentThread().getId();
    }

    public static boolean acquireLockIfPossible(VulnerabilityCaseType httpRequest) {
        return GenericHelper.acquireLockIfPossible(httpRequest, getNrSecCustomAttrName());
    }

}
