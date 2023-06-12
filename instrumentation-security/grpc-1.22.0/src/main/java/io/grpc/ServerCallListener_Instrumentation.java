package io.grpc;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.grpc1220.GrpcUtils;

@Weave(type = MatchType.BaseClass, originalName = "io.grpc.ServerCall")
public class ServerCallListener_Instrumentation {

    @Weave(type = MatchType.BaseClass, originalName = "io.grpc.ServerCall$Listener")
    public abstract static class Listener<ReqT> {
        public void onMessage(ReqT message) {
            boolean isLockAcquired = GrpcUtils.acquireLockIfPossible(message.hashCode());
            if (isLockAcquired) {
                GrpcUtils.preProcessSecurityHook(message, GrpcUtils.Type.REQUEST);
            }
            try {
                Weaver.callOriginal();
            } finally {
                if (isLockAcquired){
                    GrpcUtils.releaseLock(message.hashCode());
                }
            }
        }
    }
}
