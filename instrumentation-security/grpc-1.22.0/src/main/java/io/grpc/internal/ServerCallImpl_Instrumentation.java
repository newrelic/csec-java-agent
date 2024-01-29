package io.grpc.internal;

import com.google.protobuf.Descriptors;
import com.google.protobuf.GeneratedMessageV3;
import com.newrelic.agent.security.instrumentation.grpc1220.GrpcServerUtils;
import com.newrelic.agent.security.instrumentation.grpc1220.GrpcUtils;
import com.newrelic.api.agent.Token;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.grpc.CompressorRegistry;
import io.grpc.Context;
import io.grpc.DecompressorRegistry;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCallListener_Instrumentation;
import io.grpc.Status;
import io.perfmark.Tag;

@Weave(originalName = "io.grpc.internal.ServerCallImpl")
final class ServerCallImpl_Instrumentation<ReqT, RespT> {
    @NewField
    Token tokenForCsec;

    /**
     * We use the constructor to capture the token created in the dispatcher transaction, which is
     * available on the supplied stream variable. This is later used to assign the token
     * to the listener when the newServerStreamListener method is called.
     */
    ServerCallImpl_Instrumentation(ServerStream_Instrumentation stream, MethodDescriptor<ReqT, RespT> method, Metadata inboundHeaders, Context.CancellableContext context, DecompressorRegistry decompressorRegistry, CompressorRegistry compressorRegistry, CallTracer serverCallTracer, Tag tag) {
        this.tokenForCsec = stream.tokenForCsec;
    }

    @Trace(async = true)
    ServerStreamListener newServerStreamListener(ServerCallListener_Instrumentation listener) {
        // storing transaction for linking at io.grpc.ServerCall$Listener.onMessage()
        listener.tokenForCsec = this.tokenForCsec;
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
