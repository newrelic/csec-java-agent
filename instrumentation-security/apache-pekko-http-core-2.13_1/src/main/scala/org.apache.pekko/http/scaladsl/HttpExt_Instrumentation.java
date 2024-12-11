package org.apache.pekko.http.scaladsl;

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
import org.apache.pekko.event.LoggingAdapter;
import org.apache.pekko.http.scaladsl.model.HttpRequest;
import org.apache.pekko.http.scaladsl.model.HttpResponse;
import org.apache.pekko.http.scaladsl.model.headers.RawHeader;
import org.apache.pekko.http.scaladsl.settings.ConnectionPoolSettings;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.pekko.http.scaladsl.settings.ServerSettings;
import org.apache.pekko.stream.Materializer;
import scala.Function1;
import scala.concurrent.Future;

import java.net.URI;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.pekko.http.scaladsl.HttpExt")
public class HttpExt_Instrumentation {

    // These methods are deprecated but still exist in Pekko Http Core 1.0.0.
    // They have been replaced by Http().newServerAt().bind().

    public Future<Http.ServerBinding> bindAndHandleAsync(
            Function1<HttpRequest, Future<HttpResponse>> handler,
            String interfaceString, int port,
            ConnectionContext connectionContext,
            ServerSettings settings, int parallelism,
            LoggingAdapter adapter, Materializer mat) {

        AsyncRequestHandler wrapperHandler = new AsyncRequestHandler(handler, mat.executionContext(), mat);
        handler = wrapperHandler;
        return Weaver.callOriginal();
    }

    public Future<Http.ServerBinding> bindAndHandleSync(
            Function1<HttpRequest, HttpResponse> handler,
            String interfaceString, int port,
            ConnectionContext connectionContext,
            ServerSettings settings,
            LoggingAdapter adapter, Materializer mat) {

        SyncRequestHandler wrapperHandler = new SyncRequestHandler(handler, mat);
        handler = wrapperHandler;
        return Weaver.callOriginal();
    }

    public Future<HttpResponse> singleRequest(HttpRequest httpRequest, HttpsConnectionContext connectionContext, ConnectionPoolSettings poolSettings, LoggingAdapter loggingAdapter) {

        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST, PekkoCoreUtils.NR_SEC_CUSTOM_ATTRIB_OUTBOUND_REQ);
        AbstractOperation operation = null;

        SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
        if (isLockAcquired) {
            operation = preprocessSecurityHook(httpRequest, PekkoCoreUtils.METHOD_SINGLE_REQUEST);
        }

        if (operation!=null) {
            // Add CSEC Fuzz and parent headers
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                httpRequest = (HttpRequest)httpRequest.addHeader(RawHeader.apply(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader));
            }

            String csecParaentId = securityMetaData.getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
            if(StringUtils.isNotBlank(csecParaentId)){
                httpRequest = (HttpRequest)httpRequest.addHeader(RawHeader.apply(GenericHelper.CSEC_PARENT_ID, csecParaentId));
            }

            try {
                NewRelicSecurity.getAgent().registerOperation(operation);
            } catch (Exception e) {
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, PekkoCoreUtils.PEKKO_HTTP_CORE_2_13_1, e.getMessage()), e, this.getClass().getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, PekkoCoreUtils.PEKKO_HTTP_CORE_2_13_1, e.getMessage()), e, this.getClass().getName());
            } finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add CSEC distributed tracing header
                    httpRequest = (HttpRequest)httpRequest.addHeader(RawHeader.apply(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER,
                            SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(),
                                    NewRelicSecurity.getAgent().getAgentUUID())));
                }
            }
        }

        Future<HttpResponse> returnCode;
        // Actual Call
        try {
            returnCode = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                GenericHelper.releaseLock(PekkoCoreUtils.NR_SEC_CUSTOM_ATTRIB_OUTBOUND_REQ);
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnCode;
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, PekkoCoreUtils.PEKKO_HTTP_CORE_2_13_1, ignored.getMessage()), ignored, HttpExt_Instrumentation.class.getName());
        }
    }

    private AbstractOperation preprocessSecurityHook(HttpRequest httpRequest, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()) {
                return null;
            }

            // Generate required URL
            String uri = null;
            try {
                URI methodURI = new URI(httpRequest.getUri().toString());
                uri = methodURI.toString();
                if (methodURI == null) {
                    return null;
                }
            } catch (Exception ignored){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, PekkoCoreUtils.PEKKO_HTTP_CORE_2_13_1, ignored.getMessage()), ignored, this.getClass().getName());
                return null;
            }

            return new SSRFOperation(uri, this.getClass().getName(), methodName);
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, PekkoCoreUtils.PEKKO_HTTP_CORE_2_13_1, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, PekkoCoreUtils.PEKKO_HTTP_CORE_2_13_1, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, PekkoCoreUtils.PEKKO_HTTP_CORE_2_13_1, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }
}
