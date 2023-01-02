/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.instrumentation.okhttp40.internal.http;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import okhttp3.Request;

import java.io.IOException;

@Weave(type = MatchType.Interface, originalName = "okhttp3.internal.http.ExchangeCodec")
public abstract class ExchangeCodec_Instrumentation {

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || OkhttpHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
    }

    private AbstractOperation preprocessSecurityHook (String url, String methodName){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    url == null || url.trim().isEmpty()){
                return null;
            }
            SSRFOperation ssrfOperation = new SSRFOperation(url, this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(ssrfOperation);
            return ssrfOperation;
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
            operation = preprocessSecurityHook(getUrl(request), OkhttpHelper.METHOD_EXECUTE);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
    }

}
