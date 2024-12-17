package org.asynchttpclient;

import com.newrelic.agent.security.instrumentation.org.asynchttpclient.AsynchttpHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

@Weave(type = MatchType.Interface, originalName = "org.asynchttpclient.AsyncHttpClient")
public abstract class AsyncHttpClient_Instrumentation {

    public <T> ListenableFuture<T> executeRequest(Request request, AsyncHandler<T> handler) {
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST, getNrSecCustomAttribName());
        AbstractOperation operation = null;
        if(isLockAcquired) {
            try {
                URI uri = new URI(request.getUrl());
                String scheme = uri.getScheme().toLowerCase();

                // only instrument HTTP or HTTPS calls
                if (("http".equals(scheme) || "https".equals(scheme))) {
                    operation = preprocessSecurityHook(uri.toURL().toString(), this.getClass().getName(), AsynchttpHelper.METHOD_EXECUTE);
                    Request updatedRequest = addSecurityHeaders(request, operation);
                    if (updatedRequest != null) {
                        request = updatedRequest;
                    }
                }

            } catch (URISyntaxException | MalformedURLException uriSyntaxException) {
                // if Java can't parse the URI, asynchttpclient won't be able to either
                // let's just proceed without instrumentation
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, AsynchttpHelper.ASYNC_HTTP_CLIENT_2_0_0, uriSyntaxException.getMessage()), uriSyntaxException, this.getClass().getName());
            }
        }
        ListenableFuture<T> returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                registerExitOperation(isLockAcquired, operation);
                GenericHelper.releaseLock(getNrSecCustomAttribName());
            }
        }
        return returnVal;
    }

    private String getNrSecCustomAttribName() {
        return "ASYNCHTTP_OPERATION_LOCK-";
    }

    private AbstractOperation preprocessSecurityHook(String url, String className, String methodName) {
        try {
            if (url == null || url.trim().isEmpty()) {
                return null;
            }

            SSRFOperation operation = new SSRFOperation(url,
                    className, methodName);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, AsynchttpHelper.NR_SEC_CUSTOM_ATTRIB_NAME, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, AsynchttpHelper.NR_SEC_CUSTOM_ATTRIB_NAME, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, AsynchttpHelper.NR_SEC_CUSTOM_ATTRIB_NAME, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private Request addSecurityHeaders(Request request, AbstractOperation operation) {
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

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerOperation(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, AsynchttpHelper.NR_SEC_CUSTOM_ATTRIB_NAME, ignored.getMessage()), ignored, this.getClass().getName());
        }
    }
}
