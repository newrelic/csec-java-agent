/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl;

import akka.event.LoggingAdapter;
import akka.http.scaladsl.model.HttpRequest;
import akka.http.scaladsl.model.HttpResponse;
import akka.http.scaladsl.model.headers.RawHeader;
import akka.http.scaladsl.settings.ConnectionPoolSettings;
import akka.http.scaladsl.settings.ServerSettings;
import akka.stream.Materializer;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Segment;
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
import scala.Function1;
import scala.concurrent.Future;

import java.net.URI;

@Weave(type = MatchType.ExactClass, originalName = "akka.http.scaladsl.HttpExt")
public class HttpExt_Instrumentation {

    // This method only exists to ensure that this weave module doesn't match for versions of akka-http-core-2.13 prior to 10.2.0.
    // That said, as of 10.2.0 bind, bindAndHandle, bindAndHandleSync, and bindAndHandleAsync were all deprecated in favor of newServerAt:
    //   @deprecated("Use Http.newServerAt(...)...connectionSource() to create a source that can be materialized to a binding.", since = "10.2.0")
    public ServerBuilder newServerAt(String interfaceString, int port) {
        return Weaver.callOriginal();
    }

    public Future<Http.ServerBinding> bindAndHandleAsync(
            Function1<HttpRequest, Future<HttpResponse>> handler,
            String interfaceString, int port,
            ConnectionContext connectionContext,
            ServerSettings settings, int parallelism,
            LoggingAdapter adapter, Materializer mat) {

        AkkaAsyncRequestHandler wrapperHandler = new AkkaAsyncRequestHandler(handler, mat.executionContext(), mat);
        handler = wrapperHandler;

        return Weaver.callOriginal();
    }

    public Future<Http.ServerBinding> bindAndHandleSync(
            Function1<HttpRequest, HttpResponse> handler,
            String interfaceString, int port,
            ConnectionContext connectionContext,
            ServerSettings settings,
            LoggingAdapter adapter, Materializer mat) {

        AkkaSyncRequestHandler wrapperHandler = new AkkaSyncRequestHandler(handler, mat);
        handler = wrapperHandler;

        return Weaver.callOriginal();
    }

    public Future<HttpResponse> singleRequest(HttpRequest httpRequest, HttpsConnectionContext connectionContext, ConnectionPoolSettings poolSettings,
            LoggingAdapter loggingAdapter) {
        final Segment segment = NewRelic.getAgent().getTransaction().startSegment("Akka", "singleRequest");

        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST);
        AbstractOperation operation = null;
        // Preprocess Phase
        SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
        if (isLockAcquired) {
            operation = preprocessSecurityHook(httpRequest, AkkaCoreUtils.METHOD_SINGLE_REQUEST_IMPL);
        }

        if (operation!=null) {
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                httpRequest = (HttpRequest) httpRequest.addHeader(RawHeader.apply(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader));
            }

            String csecParaentId = securityMetaData.getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
            if(StringUtils.isNotBlank(csecParaentId)){
                httpRequest = (HttpRequest) httpRequest.addHeader(RawHeader.apply(GenericHelper.CSEC_PARENT_ID, csecParaentId));
            }

            try {
                NewRelicSecurity.getAgent().registerOperation(operation);
            } catch (Exception e){
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, AkkaCoreUtils.AKKA_HTTP_CORE_2_13_10_2_0, e.getMessage()), e, this.getClass().getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, AkkaCoreUtils.AKKA_HTTP_CORE_2_13_10_2_0, e.getMessage()), e, this.getClass().getName());
            }
            finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    httpRequest = (HttpRequest) httpRequest.addHeader(RawHeader.apply(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER,
                            SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(),
                                    NewRelicSecurity.getAgent().getAgentUUID())));
                }
            }
        }

        Future<HttpResponse> returnCode = null;
        // Actual Call
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

    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, AkkaCoreUtils.AKKA_HTTP_CORE_2_13_10_2_0, ignored.getMessage()), ignored, HttpExt_Instrumentation.class.getName());
        }
    }

    private AbstractOperation preprocessSecurityHook(HttpRequest httpRequest, String methodName) {
        try {
            // Generate required URL
            URI methodURI = null;
            String uri = null;
            try {
                methodURI = new URI(httpRequest.getUri().toString());
                uri = methodURI.toString();
                if (methodURI == null) {
                    return null;
                }
            } catch (Exception ignored){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, AkkaCoreUtils.AKKA_HTTP_CORE_2_13_10_2_0, ignored.getMessage()), ignored, this.getClass().getName());
                return null;
            }

            SSRFOperation operation = new SSRFOperation(uri, this.getClass().getName(), methodName);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, AkkaCoreUtils.AKKA_HTTP_CORE_2_13_10_2_0, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            String message = "Instrumentation library: %s , error while creating operation : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, AkkaCoreUtils.AKKA_HTTP_CORE_2_13_10_2_0, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(AkkaCoreUtils.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType httpRequest) {
        try {
            return GenericHelper.acquireLockIfPossible(httpRequest, AkkaCoreUtils.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
        return false;
    }

}
