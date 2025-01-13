package io.grpc.internal;

import com.google.protobuf.Descriptors;
import com.google.protobuf.GeneratedMessageV3;
import com.newrelic.agent.security.instrumentation.grpc140.GrpcServerUtils;
import com.newrelic.agent.security.instrumentation.grpc140.GrpcUtils;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Token;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.grpc.Metadata;
import io.grpc.ServerCallListener_Instrumentation;
import io.grpc.Status;

@Weave(originalName = "io.grpc.internal.ServerCallImpl")
final class ServerCallImpl_Instrumentation<ReqT, RespT> {
    @NewField
    Token tokenForCsec;

    @Trace(async = true)
    ServerStreamListener newServerStreamListener(ServerCallListener_Instrumentation listener) {
        // storing transaction for linking at io.grpc.ServerCall$Listener.onMessage()
        listener.tokenForCsec = NewRelic.getAgent().getTransaction().getToken();
        return Weaver.callOriginal();
    }

    public void sendMessage(RespT message) {
        if (tokenForCsec != null) {
            tokenForCsec.link();
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

    @Trace(async = true)
    public void close(Status status, Metadata trailers) {
        boolean isLockAcquired = GrpcUtils.acquireLockIfPossible(status.hashCode());
        if (isLockAcquired) {
            GrpcServerUtils.postProcessSecurityHook(trailers, status.getCode().value(), this.getClass().getName(), GrpcServerUtils.METHOD_NAME_START_CALL);
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
