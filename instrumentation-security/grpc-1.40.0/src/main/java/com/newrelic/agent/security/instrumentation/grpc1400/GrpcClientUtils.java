package com.newrelic.agent.security.instrumentation.grpc1400;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import io.grpc.Metadata;

public class GrpcClientUtils {
    public static final String METHOD_NAME_START = "start";
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "NR_CSEC_GRPC_CLIENT_OPERATIONAL_LOCK_";

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

    public static AbstractOperation preprocessSecurityHook(String uri, Metadata meta, String klass) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            SSRFOperation operation = new SSRFOperation(uri, klass, METHOD_NAME_START);

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
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }


    public static void releaseLock() {
        try {
            if(NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttrName(), null);
            }
        } catch (Throwable ignored){}
    }

    private static String getNrSecCustomAttrName() {
        return GrpcClientUtils.NR_SEC_CUSTOM_ATTRIB_NAME+Thread.currentThread().getId();
    }

    public static boolean acquireLockIfPossible() {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isLockAcquired(getNrSecCustomAttrName())) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttrName(), true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    private static boolean isLockAcquired(String nrSecCustomAttrName) {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(nrSecCustomAttrName, Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }
}
