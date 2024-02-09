/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.httpclient40;

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
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.protocol.HttpContext;

import java.net.URI;
import java.net.URISyntaxException;

@Weave(type = MatchType.Interface, originalName = "org.apache.http.client.HttpClient")
public abstract class HttpClient_Instrumentation {

    public HttpResponse execute(HttpUriRequest request) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(request, request.getURI().toString(), SecurityHelper.METHOD_NAME_EXECUTE);
        }
        HttpResponse returnObj = null;
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

    public HttpResponse execute(HttpUriRequest request, HttpContext context) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(request, request.getURI().toString(), SecurityHelper.METHOD_NAME_EXECUTE);
        }
        HttpResponse returnObj = null;
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

    public HttpResponse execute(HttpHost target, HttpRequest request) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;

        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = null;
            try {
                actualURI = getUri(target, request).toString();
            } catch (Exception ignored){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, ignored.getMessage()), ignored, this.getClass().getName());
            }
            operation = preprocessSecurityHook(request, actualURI, SecurityHelper.METHOD_NAME_EXECUTE);
        }

        HttpResponse returnObj = null;
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

    public HttpResponse execute(HttpHost target, HttpRequest request, HttpContext context) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;

        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = null;
            try {
                actualURI = getUri(target, request).toString();
            } catch (Exception ignored){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, ignored.getMessage()), ignored, this.getClass().getName());
            }
            operation = preprocessSecurityHook(request, actualURI, SecurityHelper.METHOD_NAME_EXECUTE);
        }

        HttpResponse returnObj = null;
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

    public <T, R extends T> T execute(HttpUriRequest request, ResponseHandler<R> responseHandler)
            throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(request, request.getURI().toString(), SecurityHelper.METHOD_NAME_EXECUTE);
        }
        T returnObj = null;
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

    public <T, R extends T> T execute(HttpUriRequest request, ResponseHandler<R> responseHandler, HttpContext context)
            throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(request, request.getURI().toString(), SecurityHelper.METHOD_NAME_EXECUTE);
        }
        T returnObj = null;
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

    public <T, R extends T> T execute(HttpHost target, HttpRequest request, ResponseHandler<R> responseHandler)
            throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;

        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = null;
            try {
                actualURI = getUri(target, request).toString();
            } catch (Exception ignored){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, ignored.getMessage()), ignored, this.getClass().getName());
            }
            operation = preprocessSecurityHook(request, actualURI, SecurityHelper.METHOD_NAME_EXECUTE);
        }

        T returnObj = null;
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

    public <T, R extends T> T execute(HttpHost target, HttpRequest request, ResponseHandler<R> responseHandler,
                                      HttpContext context) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;

        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = null;
            try {
                actualURI = getUri(target, request).toString();
            } catch (Exception ignored){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, ignored.getMessage()), ignored, this.getClass().getName());
            }
            operation = preprocessSecurityHook(request, actualURI, SecurityHelper.METHOD_NAME_EXECUTE);
        }

        T returnObj = null;
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
        return new URI(scheme, null, target.getHostName(), target.getPort(), requestURI.getPath(), requestURI.getQuery(), null);
    }

    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, ignored.getMessage()), ignored, HttpClient_Instrumentation.class.getName());
        }
    }

    private AbstractOperation preprocessSecurityHook(HttpRequest request, String uri, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            // TODO : Need to check if this is required anymore in NR case.
//            // Add Security app topology header
//            this.addRequestProperty("K2-API-CALLER", "");

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
            }  catch (Exception e) {
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, e.getMessage()), e, this.getClass().getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, e.getMessage()), e, this.getClass().getName());
            }
            finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    request.setHeader(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID()));
                }
            }
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_4, e.getMessage()), e, this.getClass().getName());
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

}
