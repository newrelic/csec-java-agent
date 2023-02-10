/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.instrumentation.security.okhttp40.internal.http;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import okhttp3.Request;

import java.io.IOException;

@Weave(type = MatchType.Interface, originalName = "okhttp3.internal.http.ExchangeCodec")
public abstract class ExchangeCodec_Instrumentation {


    private void releaseLock() {
        try {
            OkhttpHelper.releaseLock();
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible() {
        try {
            return OkhttpHelper.acquireLockIfPossible();
        } catch (Throwable ignored) {}
        return false;
    }

    private String getUrl(Request originalRequest) {
        try {
            if (originalRequest != null) {
                return originalRequest.url().toString();
            }
        }catch (Exception ignored){}
        return null;
    }

    public void writeRequestHeaders(Request request) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = OkhttpHelper.preprocessSecurityHook(getUrl(request), this.getClass().getName(), OkhttpHelper.METHOD_EXECUTE);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        OkhttpHelper.registerExitOperation(isLockAcquired, operation);
    }

}
