/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package spray.routing;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import scala.Function1;
import scala.PartialFunction;
import spray.SprayHttpUtils;
import spray.http.HttpEntity;

@Weave(type = MatchType.ExactClass, originalName = "spray.routing.HttpServiceBase$class")
public class SprayRoutingHttpServer {

    @Trace(dispatcher = true)
    public static final void runSealedRoute$1(final HttpServiceBase $this, final RequestContext ctx, final PartialFunction sealedExceptionHandler$1, final Function1 sealedRoute$1) {
        System.out.println("Request Intercepted!!! ctx:"+ctx.request().method().name()+":"+ctx.request().protocol().value()+":"+ctx.request().uri().toString()+":"+ctx.request().headers());
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(SprayHttpUtils.getNrSecCustomAttribName());
        if (isLockAcquired) {
            SprayHttpUtils.preProcessRequestHook(ctx.request());
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
