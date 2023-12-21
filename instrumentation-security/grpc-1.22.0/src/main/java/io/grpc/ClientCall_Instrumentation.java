package io.grpc;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.grpc1220.GrpcClientUtils;

import java.net.URI;
import java.net.URISyntaxException;

@Weave(originalName = "io.grpc.ClientCall", type = MatchType.Interface)
public abstract class ClientCall_Instrumentation<ReqT, RespT> {
    @NewField
    String csecAuthority = null;
    @NewField
    MethodDescriptor<ReqT, RespT> methodDescriptor = null;

    public void start(ClientCall.Listener<RespT> var1, Metadata var2) {
        boolean isLockAcquired = GrpcClientUtils.acquireLockIfPossible();
        AbstractOperation operation = null;

        if (isLockAcquired) {
            URI uri = null;
            try {
                uri = new URI("grpc", csecAuthority, "/" + methodDescriptor.getFullMethodName(), null, null);
            } catch (URISyntaxException e) {
                // TODO: send critical log message
            }
            operation = GrpcClientUtils.preprocessSecurityHook(String.valueOf(uri), var2, this.getClass().getName());
        }

        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                GrpcClientUtils.releaseLock();
            }
        }
        GrpcClientUtils.registerExitOperation(isLockAcquired, operation);
    }
}
