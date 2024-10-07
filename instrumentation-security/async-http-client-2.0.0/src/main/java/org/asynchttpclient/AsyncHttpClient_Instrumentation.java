/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.asynchttpclient;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.org.asynchttpclient.AsynchttpHelper;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Instrumentation for the provider interface.
 */
@Weave(type = MatchType.Interface, originalName = "org.asynchttpclient.AsyncHttpClient")
public abstract class AsyncHttpClient_Instrumentation {

    public <T> ListenableFuture<T> executeRequest(Request request, AsyncHandler<T> handler) {
        URI uri = null;
        boolean isLockAcquired = AsynchttpHelper.acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            try {
                uri = new URI(request.getUrl());
                String scheme = uri.getScheme().toLowerCase();

                // only instrument HTTP or HTTPS calls
                if (("http".equals(scheme) || "https".equals(scheme))) {
                    operation = AsynchttpHelper.preprocessSecurityHook(uri.toURL().toString(), this.getClass().getName(),
                            AsynchttpHelper.METHOD_EXECUTE);
                    Request updatedRequest = AsynchttpHelper.addSecurityHeaders(request, operation);
                    if (updatedRequest != null) {
                        request = updatedRequest;
                    }
                }

            } catch (URISyntaxException | MalformedURLException uriSyntaxException) {
                // if Java can't parse the URI, asynchttpclient won't be able to either
                // let's just proceed without instrumentation
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, AsynchttpHelper.ASYNC_HTTP_CLIENT_2_0_0, uriSyntaxException.getMessage()), uriSyntaxException, this.getClass().getName());
            }
        }
        ListenableFuture<T> returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                AsynchttpHelper.releaseLock();
            }
        }
        AsynchttpHelper.registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }
}
