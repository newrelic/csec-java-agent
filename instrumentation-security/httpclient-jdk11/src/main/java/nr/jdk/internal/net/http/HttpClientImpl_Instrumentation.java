package nr.jdk.internal.net.http;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import nr.security.java.net.http.helper.SecurityHelper;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

@Weave(originalName = "jdk.internal.net.http.HttpClientImpl", type = MatchType.ExactClass)
final class HttpClientImpl_Instrumentation {
    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }

    @Trace
    private <T> CompletableFuture<HttpResponse<T>>
    sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseHandler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler, Executor exchangeExecutor) {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(request, request.uri().toString(), SecurityHelper.METHOD_NAME_SEND);
        }
        if (operation!=null) {
            request = addSecurityHeader(operation, request);
        }
        CompletableFuture<HttpResponse<T>> returnObj = null;
        // Actual Call
        try {
            returnObj = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnObj;
    }

    private AbstractOperation preprocessSecurityHook(HttpRequest request, String uri, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            SSRFOperation operation = new SSRFOperation(uri, this.getClass().getName(), methodName);
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


    private void releaseLock() {
        try {
            GenericHelper.releaseLock(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static HttpRequest addSecurityHeader(AbstractOperation operation, HttpRequest req) {
        HttpRequest updatedRequest = null;
        try {
            HttpRequest.Builder builder = NewRelicSecurity.getAgent()
                    .getSecurityMetaData()
                    .getCustomAttribute(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME + req.hashCode(), HttpRequest.Builder.class);
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                builder.setHeader(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
            }
            String csecParaentId = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
            if(StringUtils.isNotBlank(csecParaentId)){
                builder.setHeader(GenericHelper.CSEC_PARENT_ID, csecParaentId);
            }

            if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() && operation.getExecutionId() != null &&
                    !operation.getExecutionId().trim().isEmpty()) {
                updatedRequest = builder.setHeader(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER,
                        SSRFUtils.generateTracingHeaderValue(NewRelicSecurity.getAgent().getSecurityMetaData().getTracingHeaderValue(), operation.getApiID(),
                                operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID())).build();
                return updatedRequest;
            }
        } catch (Exception ignored) {
        }
        return req.newBuilder(req.uri()).build();
    }
}
