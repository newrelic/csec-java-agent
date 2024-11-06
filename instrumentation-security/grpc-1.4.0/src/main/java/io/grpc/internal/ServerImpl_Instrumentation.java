/*
 *
 *  * Copyright 2021 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package io.grpc.internal;

import com.newrelic.agent.security.instrumentation.grpc140.GrpcServerUtils;
import com.newrelic.agent.security.instrumentation.grpc140.GrpcUtils;
import com.newrelic.agent.security.instrumentation.grpc140.processor.MonitorGrpcRequestQueueThread;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.grpc.Context;
import io.grpc.Metadata;
import io.grpc.ServerMethodDefinition;

@Weave(originalName = "io.grpc.internal.ServerImpl")
public class ServerImpl_Instrumentation {

    @Weave(originalName = "io.grpc.internal.ServerImpl$ServerTransportListenerImpl")
    private static final class ServerTransportListenerImpl_Instrumentation {

        private <ReqT, RespT> ServerStreamListener startCall(ServerStream_Instrumentation stream, String fullMethodName,
                ServerMethodDefinition<ReqT, RespT> methodDef, Metadata headers,
                Context.CancellableContext context, StatsTraceContext statsTraceCtx) {
            stream.tokenForCsec = NewRelic.getAgent().getTransaction().getToken();
            MonitorGrpcRequestQueueThread.submitNewTask();
            boolean isLockAcquired = GrpcServerUtils.acquireLockIfPossible();
            try {
                if (NewRelicSecurity.isHookProcessingActive()){
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(methodDef.getMethodDescriptor().getFullMethodName());
                    NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.GRPC);
                }
            } catch (Exception e){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, GrpcUtils.GRPC_1_4_0, e.getMessage()), e, this.getClass().getName());
            }
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
