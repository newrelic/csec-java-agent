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
import akka.stream.Materializer;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.akka.core.AkkaCoreUtils;
import scala.concurrent.Future;

import java.net.URI;

@Weave(type = MatchType.ExactClass, originalName = "akka.http.scaladsl.HttpExt")
public class HttpExt_Instrumentation {

    // We are weaving the singleRequestImpl method here rather than just singleRequest because the javadsl only flows through here
    public Future<HttpResponse> singleRequest(HttpRequest httpRequest, HttpsConnectionContext connectionContext, ConnectionPoolSettings settings,
                                              LoggingAdapter log, Materializer fm) {

        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(httpRequest, AkkaCoreUtils.METHOD_SINGLE_REQUEST_IMPL);
        }
        if(operation!=null){
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            // Add Security IAST header
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
            } finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    httpRequest = (HttpRequest) httpRequest.addHeader(RawHeader.apply(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID())));
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
        }
    }

    private AbstractOperation preprocessSecurityHook(HttpRequest httpRequest, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()) {
                return null;
            }

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
                String message = "Instrumentation library: %s , error while extracting URI : %s";
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, "AKKA_HTTP_CORE_10.0", ignored.getMessage()), ignored, this.getClass().getName());
                return null;
            }
            SSRFOperation operation = new SSRFOperation(uri, this.getClass().getName(), methodName);
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
            GenericHelper.releaseLock(AkkaCoreUtils.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(AkkaCoreUtils.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
        return false;
    }

}
