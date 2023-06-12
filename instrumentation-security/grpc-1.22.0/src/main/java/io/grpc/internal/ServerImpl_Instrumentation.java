/*
 *
 *  * Copyright 2021 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package io.grpc.internal;

import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.grpc1220.GrpcServerUtils;
import io.grpc.Context;
import io.grpc.Metadata;
import io.grpc.ServerMethodDefinition;
import io.perfmark.Tag;

@Weave(originalName = "io.grpc.internal.ServerImpl")
public class ServerImpl_Instrumentation {

    @Weave(originalName = "io.grpc.internal.ServerImpl$ServerTransportListenerImpl")
    private static final class ServerTransportListenerImpl_Instrumentation {

        private <ReqT, RespT> ServerStreamListener startCall(ServerStream stream, String fullMethodName,
                ServerMethodDefinition<ReqT, RespT> methodDef, Metadata headers,
                Context.CancellableContext context, StatsTraceContext statsTraceCtx, Tag tag) {
            boolean isLockAcquired = GrpcServerUtils.acquireLockIfPossible();

            if (isLockAcquired) {
                GrpcServerUtils.preprocessSecurityHook(stream, methodDef, headers, this.getClass().getName());
            }
            ServerStreamListener returnVal;
            try {
                returnVal =  Weaver.callOriginal();
            } finally {
                if (isLockAcquired) {
                    GrpcServerUtils.releaseLock();
                }
            }
            return returnVal;
        }
    }

}
