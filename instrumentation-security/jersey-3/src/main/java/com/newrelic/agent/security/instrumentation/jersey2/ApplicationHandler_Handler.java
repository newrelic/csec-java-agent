/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.jersey2;

import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.glassfish.jersey.server.ContainerRequest;

@Weave(type = MatchType.ExactClass, originalName = "org.glassfish.jersey.server.ApplicationHandler")
public final class ApplicationHandler_Handler {

    public void handle(final ContainerRequest request) {
        boolean isRequestLockAcquired = false;
        try {
            if (request != null) {
                isRequestLockAcquired = HttpRequestHelper.acquireRequestLockIfPossible();
                if (isRequestLockAcquired) {
                    GenericHelper.acquireLockIfPossible(HttpRequestHelper.getNrSecCustomAttribForPostProcessing());
                    HttpRequestHelper.preprocessSecurityHook(request);
                    HttpRequestHelper.registerUserLevelCode("JERSEY");
                }
            }
            Weaver.callOriginal();
        } finally {
            if(isRequestLockAcquired){
                GenericHelper.releaseLock(HttpRequestHelper.getNrSecCustomAttribForPostProcessing());
                HttpRequestHelper.releaseRequestLock();
            }
        }
    }

}
