/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.httpasyncclient4;

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

import static com.newrelic.agent.security.instrumentation.httpasyncclient4.SecurityHelper.HTTP_ASYNC_CLIENT_4;

@Weave(type = MatchType.Interface, originalName = "org.apache.http.nio.client.HttpAsyncClient")
public class HttpAsyncClient4_Instrumentation {

    public <T> Future<T> execute(HttpAsyncRequestProducer requestProducer, HttpAsyncResponseConsumer<T> responseConsumer, HttpContext context, FutureCallback<T> callback) {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST);
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            try {
                HttpRequest request = requestProducer.generateRequest();
                // Preprocess Phase
                operation = preprocessSecurityHook(request, request.getRequestLine().getUri(), SecurityHelper.METHOD_NAME_EXECUTE);
            } catch (Throwable ignored) {
            }
        }

        Future<T> returnObj = null;
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

    public <T> Future<T> execute(HttpAsyncRequestProducer requestProducer, HttpAsyncResponseConsumer<T> responseConsumer, FutureCallback<T> callback) {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST);
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            try {
                HttpRequest request = requestProducer.generateRequest();
                // Preprocess Phase
                operation = preprocessSecurityHook(request, request.getRequestLine().getUri(), SecurityHelper.METHOD_NAME_EXECUTE);
            } catch (Throwable ignored) {
            }
        }

        Future<T> returnObj = null;
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

    public Future<HttpResponse> execute(HttpHost target, HttpRequest request, HttpContext context, FutureCallback<HttpResponse> callback) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST);
        AbstractOperation operation = null;

        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = null;
            try {
                actualURI = getUri(target, request).toString();
            } catch (Exception ignored){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, HTTP_ASYNC_CLIENT_4, ignored.getMessage()), ignored, this.getClass().getName());
            }
            operation = preprocessSecurityHook(request, actualURI, SecurityHelper.METHOD_NAME_EXECUTE);
        }

        Future<HttpResponse> returnObj = null;
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

    public Future<HttpResponse> execute(HttpHost target, HttpRequest request, FutureCallback<HttpResponse> callback) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST);
        AbstractOperation operation = null;

        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = null;
            try {
                actualURI = getUri(target, request).toString();
            } catch (Exception ignored){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, HTTP_ASYNC_CLIENT_4, ignored.getMessage()), ignored, this.getClass().getName());
            }
            operation = preprocessSecurityHook(request, actualURI, SecurityHelper.METHOD_NAME_EXECUTE);
        }

        Future<HttpResponse> returnObj = null;
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

    public Future<HttpResponse> execute(HttpUriRequest request, HttpContext context, FutureCallback<HttpResponse> callback) {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST);
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(request, request.getURI().toString(), SecurityHelper.METHOD_NAME_EXECUTE);
        }
        Future<HttpResponse> returnObj = null;
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

    public Future<HttpResponse> execute(HttpUriRequest request, FutureCallback<HttpResponse> callback) {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST);
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(request, request.getURI().toString(), SecurityHelper.METHOD_NAME_EXECUTE);
        }
        Future<HttpResponse> returnObj = null;
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


    private static URI getUri(HttpHost target, HttpRequest request) throws URISyntaxException {
        URI requestURI = new URI(request.getRequestLine().getUri());
        String scheme = requestURI.getScheme() == null ? target.getSchemeName() : requestURI.getScheme();
        return new URI(scheme, null, target.getHostName(), target.getPort(), requestURI.getPath(),
                requestURI.getQuery(), null);
    }

    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, HTTP_ASYNC_CLIENT_4, ignored.getMessage()), ignored, HttpAsyncClient4_Instrumentation.class.getName());
        }
    }

    private AbstractOperation preprocessSecurityHook(HttpRequest request, String uri, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            // Add Security IAST header
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                request.setHeader(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
            }

            String csecParaentId = securityMetaData.getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
            if(StringUtils.isNotBlank(csecParaentId)){
                request.setHeader(GenericHelper.CSEC_PARENT_ID, csecParaentId);
            }

            SSRFOperation operation = new SSRFOperation(uri,
                    this.getClass().getName(), methodName);
            try {
                NewRelicSecurity.getAgent().registerOperation(operation);
            } finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    request.setHeader(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID()));
                }
            }
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, HTTP_ASYNC_CLIENT_4, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HTTP_ASYNC_CLIENT_4, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HTTP_ASYNC_CLIENT_4, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType httpRequest) {
        try {
            return GenericHelper.acquireLockIfPossible(httpRequest, SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
        return false;
    }
}
