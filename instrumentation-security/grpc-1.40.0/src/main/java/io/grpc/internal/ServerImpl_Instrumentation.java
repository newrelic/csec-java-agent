package io.grpc.internal;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.grpc1400.GrpcServerUtils;
import com.newrelic.agent.security.instrumentation.grpc1400.processor.MonitorGrpcRequestQueueThread;
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
