/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package io.grpc.internal;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.grpc140.GrpcServerUtils;
import com.newrelic.agent.security.instrumentation.grpc140.GrpcUtils;
import io.grpc.Metadata;
import io.grpc.Status;

@Weave(originalName = "io.grpc.internal.ServerCallImpl")
final class ServerCallImpl_Instrumentation<ReqT, RespT> {

    @Trace(async = true)
    public void sendMessage(RespT message) {
        boolean isLockAcquired = GrpcUtils.acquireLockIfPossible(message.hashCode());
        if (isLockAcquired) {
            GrpcUtils.preProcessSecurityHook(message, GrpcUtils.Type.RESPONSE);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired){
                GrpcUtils.releaseLock(message.hashCode());
            }
        }
    }

    @Trace(async = true)
    public void close(Status status, Metadata trailers) {
        boolean isLockAcquired = GrpcUtils.acquireLockIfPossible(status.hashCode());
        if (isLockAcquired) {
            GrpcServerUtils.postProcessSecurityHook(trailers, this.getClass().getName(), GrpcServerUtils.METHOD_NAME_START_CALL);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired){
                GrpcUtils.releaseLock(status.hashCode());
            }
        }
    }
}
