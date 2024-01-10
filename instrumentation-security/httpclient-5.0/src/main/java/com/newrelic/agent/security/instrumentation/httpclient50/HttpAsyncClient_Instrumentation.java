/*
 *
 *  * Copyright 2023 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.httpclient50;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.nio.AsyncPushConsumer;
import org.apache.hc.core5.http.nio.AsyncRequestProducer;
import org.apache.hc.core5.http.nio.AsyncResponseConsumer;
import org.apache.hc.core5.http.nio.HandlerFactory;
import org.apache.hc.core5.http.protocol.HttpContext;

import java.net.URISyntaxException;
import java.util.concurrent.Future;

import static com.newrelic.agent.security.instrumentation.httpclient50.SecurityHelper.APACHE5_ASYNC_REQUEST_PRODUCER;

@Weave(type = MatchType.Interface, originalName = "org.apache.hc.client5.http.async.HttpAsyncClient")
public class HttpAsyncClient_Instrumentation {

    public <T> Future<T> execute(
            AsyncRequestProducer requestProducer,
            AsyncResponseConsumer<T> responseConsumer,
            HandlerFactory<AsyncPushConsumer> pushHandlerFactory,
            HttpContext context,
            FutureCallback<T> callback) {
        HttpRequest request = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(APACHE5_ASYNC_REQUEST_PRODUCER+requestProducer.hashCode(), HttpRequest.class);

        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            try {
                operation = SecurityHelper.preprocessSecurityHook(request, request.getUri().toString(), this.getClass().getName(), SecurityHelper.METHOD_NAME_EXECUTE);
            } catch (URISyntaxException e) {
                String message = "Instrumentation library: %s , error while get URI : %s";
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, "HTTPCLIENT-5.0", e.getMessage()), e, this.getClass().getName());
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
        SecurityHelper.registerExitOperation(isLockAcquired, operation);
        return returnObj;
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
