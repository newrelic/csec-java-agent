/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package spray.can.server;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import spray.can.SprayHttpUtils;
import spray.http.HttpRequest;

@Weave(originalName = "spray.can.server.ServerFrontend$$anon$2$$anon$1")
public class ServerFrontend_Instrumentation {

    public void spray$can$server$ServerFrontend$$anon$$anon$$openNewRequest(final HttpRequest request,
            final boolean closeAfterResponseCompletion, final RequestState state) {
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(SprayHttpUtils.getNrSecCustomAttribName());
        if (isLockAcquired) {
            SprayHttpUtils.preProcessRequestHook(request);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                GenericHelper.releaseLock(SprayHttpUtils.getNrSecCustomAttribName());
            }
        }
    }
}
