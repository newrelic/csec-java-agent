package io.grpc;

import com.google.protobuf.Descriptors;
import com.google.protobuf.GeneratedMessageV3;
import com.newrelic.agent.security.instrumentation.grpc1220.GrpcServerUtils;
import com.newrelic.api.agent.Token;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.grpc1220.GrpcUtils;

@Weave(type = MatchType.BaseClass, originalName = "io.grpc.ServerCall$Listener")
public abstract class ServerCallListener_Instrumentation<ReqT> {
    @NewField
    public Token tokenForCsec;

    public void onMessage(ReqT message) {
        // linking transaction
        if (tokenForCsec != null) {
            tokenForCsec.link();
        }
        Descriptors.Descriptor descriptorForType = ((GeneratedMessageV3) message).getDescriptorForType();
        GrpcServerUtils.createTypeRegistries(descriptorForType);
        boolean isLockAcquired = GrpcUtils.acquireLockIfPossible(message.hashCode());
        if (isLockAcquired) {
            GrpcUtils.preProcessSecurityHook(message, GrpcUtils.Type.REQUEST, descriptorForType.getFullName());
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired){
                GrpcUtils.releaseLock(message.hashCode());
            }
        }
    }

    public void onHalfClose() {
        if (tokenForCsec != null) {
            tokenForCsec = null;
        }
        Weaver.callOriginal();
    }
}

