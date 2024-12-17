/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.okhttp35.http;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.okhttp35.OkhttpHelper;
import okhttp3.Request;

@Weave(type = MatchType.Interface, originalName = "okhttp3.internal.http.HttpCodec")
public abstract class HttpCodec_Instrumentation {

    public void writeRequestHeaders(Request request) {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST);
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
                OkhttpHelper.registerExitOperation(isLockAcquired, operation);
                releaseLock();
            }
        }
    }

    private void releaseLock() {
        GenericHelper.releaseLock(OkhttpHelper.getNrSecCustomAttribName());
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType httpRequest) {
        return GenericHelper.acquireLockIfPossible(httpRequest, OkhttpHelper.getNrSecCustomAttribName());
    }

    private String getUrl(Request originalRequest) {
        try {
            if (originalRequest != null) {
                return originalRequest.url().toString();
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, OkhttpHelper.OKHTTP_3_5_0, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

}
