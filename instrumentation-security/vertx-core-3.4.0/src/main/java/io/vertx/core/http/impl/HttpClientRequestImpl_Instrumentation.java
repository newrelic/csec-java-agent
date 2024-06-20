package io.vertx.core.http.impl;

import com.newrelic.agent.security.instrumentation.vertx.VertxClientHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.impl.VertxInternal;

@Weave(originalName = "io.vertx.core.http.impl.HttpClientRequestImpl")
public abstract class HttpClientRequestImpl_Instrumentation {
    public abstract MultiMap headers();
    public abstract String absoluteURI();

    HttpClientRequestImpl_Instrumentation(HttpClientImpl client, boolean ssl, HttpMethod method, String host, int port, String relativeURI, VertxInternal vertx){
        // this is necessary to remove instrumentation on vertx-core within version range [3.7.1,4.0.0.Beta1)
    }

    public void end(Buffer chunk) {
        boolean isLockAcquired = VertxClientHelper.acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(absoluteURI(), this.getClass().getName(), VertxClientHelper.METHOD_END);
            addSecurityHeaders(headers(), operation);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                VertxClientHelper.releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
    }

    public void end() {
        boolean isLockAcquired = VertxClientHelper.acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(absoluteURI(), this.getClass().getName(), VertxClientHelper.METHOD_END);
            addSecurityHeaders(headers(), operation);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                VertxClientHelper.releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
    }
    private AbstractOperation preprocessSecurityHook(String url, String className, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || url == null || url.trim().isEmpty()) {
                return null;
            }
            SSRFOperation operation = new SSRFOperation(url, className, methodName);
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, VertxClientHelper.VERTX_CORE_3_4_0, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, VertxClientHelper.VERTX_CORE_3_4_0, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, VertxClientHelper.VERTX_CORE_3_4_0, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private void addSecurityHeaders(MultiMap headers, AbstractOperation operation) {
        if (operation == null || headers == null) {
            return;
        }

        // Add Security IAST header
        String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
        if (iastHeader != null && !iastHeader.trim().isEmpty()) {
            headers.add(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
        }

        String csecParaentId = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
        if(StringUtils.isNotBlank(csecParaentId)){
            headers.add(GenericHelper.CSEC_PARENT_ID, csecParaentId);
        }

        if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
            // Add Security distributed tracing header
            headers.remove(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            headers.add(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER,
                    SSRFUtils.generateTracingHeaderValue(NewRelicSecurity.getAgent().getSecurityMetaData()
                                    .getTracingHeaderValue(),
                            operation.getApiID(), operation.getExecutionId(),
                            NewRelicSecurity.getAgent().getAgentUUID()));
        }
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, VertxClientHelper.VERTX_CORE_3_4_0, e.getMessage()), e, this.getClass().getName());
        }
    }
}
