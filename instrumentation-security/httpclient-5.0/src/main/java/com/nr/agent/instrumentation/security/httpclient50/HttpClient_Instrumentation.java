/*
 *
 *  * Copyright 2023 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.instrumentation.security.httpclient50;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.protocol.HttpContext;

import java.net.URI;
import java.net.URISyntaxException;

@Weave(type = MatchType.Interface, originalName = "org.apache.hc.client5.http.classic.HttpClient")
public class HttpClient_Instrumentation {

    public HttpResponse execute(ClassicHttpRequest request) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = SecurityHelper.preprocessSecurityHook(request, request.getUri().toString(), this.getClass().getName(), SecurityHelper.METHOD_NAME_EXECUTE);
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
        SecurityHelper.registerExitOperation(isLockAcquired, operation);
        return returnObj;
    }

    public HttpResponse execute(ClassicHttpRequest request, HttpContext context) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = SecurityHelper.preprocessSecurityHook(request, request.getUri().toString(), this.getClass().getName(), SecurityHelper.METHOD_NAME_EXECUTE);
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
        SecurityHelper.registerExitOperation(isLockAcquired, operation);
        return returnObj;
    }

    public ClassicHttpResponse execute(HttpHost target, ClassicHttpRequest request) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = getUri(target, request).toString();
            operation = SecurityHelper.preprocessSecurityHook(request, actualURI, this.getClass().getName(), SecurityHelper.METHOD_NAME_EXECUTE);
        }
        ClassicHttpResponse returnObj = null;
        // Actual Call
        try {
            returnObj = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        SecurityHelper.registerExitOperation(isLockAcquired, operation);
        return returnObj;
    }

    public HttpResponse execute(HttpHost target, ClassicHttpRequest request, HttpContext context) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = getUri(target, request).toString();
            operation = SecurityHelper.preprocessSecurityHook(request, actualURI, this.getClass().getName(), SecurityHelper.METHOD_NAME_EXECUTE);
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
        SecurityHelper.registerExitOperation(isLockAcquired, operation);
        return returnObj;
    }

    public <T> T execute(ClassicHttpRequest request, HttpClientResponseHandler<? extends T> responseHandler)
            throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = SecurityHelper.preprocessSecurityHook(request, request.getUri().toString(), this.getClass().getName(), SecurityHelper.METHOD_NAME_EXECUTE);
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
        SecurityHelper.registerExitOperation(isLockAcquired, operation);
        return returnObj;
    }

    public <T> T execute(ClassicHttpRequest request, HttpContext context, HttpClientResponseHandler<? extends T> responseHandler)
            throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = SecurityHelper.preprocessSecurityHook(request, request.getUri().toString(), this.getClass().getName(), SecurityHelper.METHOD_NAME_EXECUTE);
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
        SecurityHelper.registerExitOperation(isLockAcquired, operation);
        return returnObj;
    }

    public <T> T execute(HttpHost target, ClassicHttpRequest request, HttpClientResponseHandler<? extends T> responseHandler)
            throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = getUri(target, request).toString();
            operation = SecurityHelper.preprocessSecurityHook(request, actualURI, this.getClass().getName(), SecurityHelper.METHOD_NAME_EXECUTE);
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
        SecurityHelper.registerExitOperation(isLockAcquired, operation);
        return returnObj;
    }

    public <T> T execute(HttpHost target, ClassicHttpRequest request, HttpContext context,
            HttpClientResponseHandler<? extends T> responseHandler) throws Exception {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            String actualURI = getUri(target, request).toString();
            operation = SecurityHelper.preprocessSecurityHook(request, actualURI, this.getClass().getName(), SecurityHelper.METHOD_NAME_EXECUTE);
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
        SecurityHelper.registerExitOperation(isLockAcquired, operation);
        return returnObj;
    }

    private static URI getUri(HttpHost target, HttpRequest request) throws URISyntaxException {
        URI requestURI = new URI(request.getRequestUri());
        String scheme = requestURI.getScheme() == null ? target.getSchemeName() : requestURI.getScheme();
        return new URI(scheme, null, target.getHostName(), target.getPort(), requestURI.getPath(), null, null);
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
