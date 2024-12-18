package io.grpc;

import com.google.protobuf.Descriptors;
import com.google.protobuf.GeneratedMessageV3;
import com.newrelic.agent.security.instrumentation.grpc1400.GrpcServerUtils;
import com.newrelic.agent.security.instrumentation.grpc1400.GrpcUtils;
import com.newrelic.api.agent.Token;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.Arrays;

@Weave(type = MatchType.BaseClass, originalName = "io.grpc.ServerCall$Listener")
public abstract class ServerCallListener_Instrumentation<ReqT> {
    @NewField
    public Token tokenForCsec;

    @Trace(async = true)
    public void onMessage(ReqT message) {
        // linking transaction
        if (tokenForCsec != null) {
            tokenForCsec.link();
        }
        Descriptors.Descriptor descriptorForType = ((GeneratedMessageV3) message).getDescriptorForType();
        GrpcServerUtils.addToTypeRegistries(descriptorForType);
        boolean isLockAcquired = GrpcUtils.acquireLockIfPossible(message.hashCode());
        if (isLockAcquired) {
            GrpcUtils.preProcessSecurityHook(message, GrpcUtils.Type.REQUEST, descriptorForType.getFullName());
        }
        ServletHelper.registerUserLevelCode(Framework.GRPC.name());
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                GrpcUtils.releaseLock(message.hashCode());
            }
        }
    }

    public void onHalfClose() {
        if (NewRelicSecurity.isHookProcessingActive()) {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            StackTraceElement[] trace = (new Exception()).getStackTrace();
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 1, trace.length));
        }
        if (tokenForCsec != null) {
            tokenForCsec = null;
        }
        Weaver.callOriginal();
    }
}
