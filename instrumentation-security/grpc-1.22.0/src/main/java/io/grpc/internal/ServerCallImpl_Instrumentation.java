/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package io.grpc.internal;

import com.google.protobuf.Descriptors;
import com.google.protobuf.GeneratedMessageV3;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Token;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.grpc1220.GrpcServerUtils;
import com.newrelic.agent.security.instrumentation.grpc1220.GrpcUtils;
import io.grpc.Metadata;
import io.grpc.ServerCallListener_Instrumentation;
import io.grpc.Status;

@Weave(originalName = "io.grpc.internal.ServerCallImpl")
final class ServerCallImpl_Instrumentation<ReqT, RespT> {
    ServerStreamListener newServerStreamListener(ServerCallListener_Instrumentation listener) {
        ServerStreamListener serverStreamListener = Weaver.callOriginal();
        // storing transaction for linking at io.grpc.ServerCall$Listener.onMessage()
        listener.tokenForCsec = NewRelic.getAgent().getTransaction().getToken();
        return serverStreamListener;
    }

    public void sendMessage(RespT message) {
        // linking transaction
        Token csecToken = NewRelic.getAgent().getTransaction().getToken();
        if (csecToken != null) {
            csecToken.link();
        }
        Descriptors.Descriptor descriptorForType = ((GeneratedMessageV3) message).getDescriptorForType();
        boolean isLockAcquired = GrpcUtils.acquireLockIfPossible(message.hashCode());
        if (isLockAcquired) {
            GrpcUtils.preProcessSecurityHook(message, GrpcUtils.Type.RESPONSE, descriptorForType.getFullName());
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired){
                GrpcUtils.releaseLock(message.hashCode());
            }
        }
    }

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
