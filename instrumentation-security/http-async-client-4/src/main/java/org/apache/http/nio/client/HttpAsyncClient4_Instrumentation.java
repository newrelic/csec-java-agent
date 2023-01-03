/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.apache.http.nio.client;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.constants.AgentConstants;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.agent.instrumentation.security.httpasyncclient4.SecurityHelper;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.nio.protocol.HttpAsyncRequestProducer;
import org.apache.http.nio.protocol.HttpAsyncResponseConsumer;
import org.apache.http.protocol.HttpContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.Future;


@Weave(type = MatchType.Interface, originalName = "org.apache.http.nio.client.HttpAsyncClient")
public class HttpAsyncClient4_Instrumentation {

    @NewField
    public boolean cascadedCall;

    public <T> Future<T> execute(HttpAsyncRequestProducer requestProducer, HttpAsyncResponseConsumer<T> responseConsumer, HttpContext context, FutureCallback<T> callback) {
        boolean currentCascadedCall = cascadedCall;

        AbstractOperation operation = null;
        try {
            HttpRequest request = requestProducer.generateRequest();
            // Preprocess Phase
            operation = preprocessSecurityHook(currentCascadedCall, request, requestProducer.getTarget().toString(), SecurityHelper.METHOD_NAME_EXECUTE);
        } catch (Throwable ignored) {
        }

        Future<T> returnObj = null;
        // Actual Call
        try {
            returnObj = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }
        registerExitOperation(operation);
        return returnObj;
    }

    public <T> Future<T> execute(HttpAsyncRequestProducer requestProducer, HttpAsyncResponseConsumer<T> responseConsumer, FutureCallback<T> callback) {
        boolean currentCascadedCall = cascadedCall;

        AbstractOperation operation = null;
        try {
            final HttpRequest request = requestProducer.generateRequest();
            // Preprocess Phase
            operation = preprocessSecurityHook(currentCascadedCall, request, requestProducer.getTarget().toString(), SecurityHelper.METHOD_NAME_EXECUTE);
        } catch (Throwable ignored) {
        }

        Future<T> returnObj = null;
        // Actual Call
        try {
            returnObj = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }
        registerExitOperation(operation);
        return returnObj;
    }

    public Future<HttpResponse> execute(HttpHost target, HttpRequest request, HttpContext context, FutureCallback<HttpResponse> callback) throws Exception {
        String actualURI = getUri(target, request).toString();
        boolean currentCascadedCall = cascadedCall;
        // Preprocess Phase
        AbstractOperation operation = preprocessSecurityHook(currentCascadedCall, request, actualURI, SecurityHelper.METHOD_NAME_EXECUTE);

        Future<HttpResponse> returnObj = null;
        // Actual Call
        try {
            returnObj = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }
        registerExitOperation(operation);
        return returnObj;
    }

    public Future<HttpResponse> execute(HttpHost target, HttpRequest request, FutureCallback<HttpResponse> callback) throws Exception {
        String actualURI = getUri(target, request).toString();
        boolean currentCascadedCall = cascadedCall;
        // Preprocess Phase
        AbstractOperation operation = preprocessSecurityHook(currentCascadedCall, request, actualURI, SecurityHelper.METHOD_NAME_EXECUTE);

        Future<HttpResponse> returnObj = null;
        // Actual Call
        try {
            returnObj = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }
        registerExitOperation(operation);
        return returnObj;
    }

    public Future<HttpResponse> execute(HttpUriRequest request, HttpContext context, FutureCallback<HttpResponse> callback) {
        boolean currentCascadedCall = cascadedCall;
        // Preprocess Phase
        AbstractOperation operation = preprocessSecurityHook(currentCascadedCall, request, request.getURI().toString(), SecurityHelper.METHOD_NAME_EXECUTE);

        Future<HttpResponse> returnObj = null;
        // Actual Call
        try {
            returnObj = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }
        registerExitOperation(operation);
        return returnObj;
    }

    public Future<HttpResponse> execute(HttpUriRequest request, FutureCallback<HttpResponse> callback) {
        boolean currentCascadedCall = cascadedCall;
        // Preprocess Phase
        AbstractOperation operation = preprocessSecurityHook(currentCascadedCall, request, request.getURI().toString(), SecurityHelper.METHOD_NAME_EXECUTE);

        Future<HttpResponse> returnObj = null;
        // Actual Call
        try {
            returnObj = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }
        registerExitOperation(operation);
        return returnObj;
    }


    private static URI getUri(HttpHost target, HttpRequest request) throws URISyntaxException {
        URI requestURI = new URI(request.getRequestLine().getUri());
        String scheme = requestURI.getScheme() == null ? target.getSchemeName() : requestURI.getScheme();
        return new URI(scheme, null, target.getHostName(), target.getPort(), requestURI.getPath(), null, null);
    }

    private static void registerExitOperation(AbstractOperation operation) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }

    private AbstractOperation preprocessSecurityHook(boolean currentCascadedCall, HttpRequest request, String uri, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
                    || currentCascadedCall
            ) {
                return null;
            }
            cascadedCall = true;

            // Add Security IAST header
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                request.setHeader(AgentConstants.K2_FUZZ_REQUEST_ID, iastHeader);
            }

            SSRFOperation operation = new SSRFOperation(uri,
                    this.getClass().getName(), methodName);
            try {
                NewRelicSecurity.getAgent().registerOperation(operation);
            } finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    request.setHeader(AgentConstants.K2_TRACING_DATA, SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID()));
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
}
