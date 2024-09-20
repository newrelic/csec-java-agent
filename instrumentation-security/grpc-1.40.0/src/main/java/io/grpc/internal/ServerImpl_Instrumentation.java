package io.grpc.internal;

import com.newrelic.agent.security.instrumentation.grpc1400.GrpcServerUtils;
import com.newrelic.agent.security.instrumentation.grpc1400.GrpcUtils;
import com.newrelic.agent.security.instrumentation.grpc1400.processor.MonitorGrpcRequestQueueThread;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.grpc.Metadata;
import io.grpc.ServerMethodDefinition;
import io.perfmark.Tag;

@Weave(originalName = "io.grpc.internal.ServerImpl")
public class ServerImpl_Instrumentation {

    @Weave(originalName = "io.grpc.internal.ServerImpl$ServerTransportListenerImpl")
    private static final class ServerTransportListenerImpl_Instrumentation {

        @NewField
        private Metadata headers;

        private void streamCreatedInternal(final ServerStream stream, final String methodName, final Metadata headers, final Tag tag) {
            MonitorGrpcRequestQueueThread.submitNewTask();
            this.headers = headers;
            Weaver.callOriginal();
        }

        private <ReqT, RespT> ServerMethodDefinition<?, ?> wrapMethod(ServerStream_Instrumentation stream, ServerMethodDefinition<ReqT, RespT> methodDef, StatsTraceContext statsTraceCtx) {
            stream.tokenForCsec = NewRelic.getAgent().getTransaction().getToken();
            boolean isLockAcquired = GrpcServerUtils.acquireLockIfPossible();
            try {
                if (NewRelicSecurity.isHookProcessingActive()){
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setRoute(methodDef.getMethodDescriptor().getFullMethodName());
                    NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.GRPC);
                }
            } catch (Exception e) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, GrpcUtils.GRPC_1_40_0, e.getMessage()), e, this.getClass().getName());
            }
            if (isLockAcquired) {
                GrpcServerUtils.preprocessSecurityHook(stream, methodDef, headers, this.getClass().getName());
            }
            ServerMethodDefinition returnVal;
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
