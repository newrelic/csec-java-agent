/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.okhttp35.http;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.okhttp35.OkhttpHelper;
import okhttp3.Request;

@Weave(type = MatchType.Interface, originalName = "okhttp3.internal.http.HttpCodec")
public abstract class HttpCodec_Instrumentation {

    public void writeRequestHeaders(Request request) {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = OkhttpHelper.preprocessSecurityHook(getUrl(request), this.getClass().getName(),
                    OkhttpHelper.METHOD_EXECUTE);
            Request updatedRequest = OkhttpHelper.addSecurityHeaders(request.newBuilder(), operation);
            if (updatedRequest != null) {
                request = updatedRequest;
            }
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        OkhttpHelper.registerExitOperation(isLockAcquired, operation);
    }

    private void releaseLock() {
        try {
            OkhttpHelper.releaseLock();
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible() {
        try {
            return OkhttpHelper.acquireLockIfPossible();
        } catch (Throwable ignored) {
        }
        return false;
    }

    private String getUrl(Request originalRequest) {
        try {
            if (originalRequest != null) {
                return originalRequest.url().toString();
            }
        } catch (Exception e) {
            String message = "Instrumentation library: %s , error while generating request URI : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, "OKHTTP-3.5.0", e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

}
