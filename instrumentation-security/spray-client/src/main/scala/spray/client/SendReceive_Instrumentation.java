package spray.client;

import com.newrelic.agent.security.instrumentation.spray.client.OutboundRequest;
import com.newrelic.agent.security.instrumentation.spray.client.SprayUtils;
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
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import scala.concurrent.Future;
import spray.http.HttpRequest;
import spray.http.HttpResponse;

import java.net.URI;

@Weave(type = MatchType.Interface, originalName = "spray.client.pipelining$$anonfun$sendReceive$1")
public class SendReceive_Instrumentation {

    public final Future<HttpResponse> apply(HttpRequest request) {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(request);
            request = addSecurityHeaders(request, operation);
        }

        Future<HttpResponse> returnCode;
        try {
            returnCode = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnCode;
    }

    private HttpRequest addSecurityHeaders(HttpRequest request, AbstractOperation operation) {
        OutboundRequest outboundRequest = new OutboundRequest(request);
        if (operation!=null) {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                outboundRequest.setHeader(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
            }
            String csecParentId = securityMetaData.getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
            if(StringUtils.isNotBlank(csecParentId)){
                outboundRequest.setHeader(GenericHelper.CSEC_PARENT_ID, csecParentId);
            }

            try {
                NewRelicSecurity.getAgent().registerOperation(operation);
            } finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    outboundRequest.setHeader(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER,
                        SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(),
                                operation.getApiID(), operation.getExecutionId(),
                                NewRelicSecurity.getAgent().getAgentUUID()));
                }
            }
        }
        return outboundRequest.getRequest();
    }

    private void releaseLock() {
        GenericHelper.releaseLock(SprayUtils.getNrSecCustomAttribName());
    }

    private boolean acquireLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.REFLECTED_XSS, SprayUtils.getNrSecCustomAttribName());
    }

    private AbstractOperation preprocessSecurityHook(HttpRequest httpRequest) {
        try {
            // Generate required URL
            URI methodURI = null;
            String uri = null;
            try {
                methodURI = new URI(httpRequest.uri().toString());
                uri = methodURI.toString();
                if (methodURI == null) {
                    return null;
                }
            } catch (Exception ignored){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, SprayUtils.SPRAY_CLIENT, ignored.getMessage()), ignored, this.getClass().getName());
                return null;
            }
            return new SSRFOperation(uri, this.getClass().getName(), SprayUtils.METHOD_SEND_RECEIVE);
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, SprayUtils.SPRAY_CLIENT, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SprayUtils.SPRAY_CLIENT, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SprayUtils.SPRAY_CLIENT, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }
    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, SprayUtils.SPRAY_CLIENT, e.getMessage()), e, this.getClass().getName());
        }
    }
}

