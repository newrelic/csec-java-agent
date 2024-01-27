package io.grpc;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(originalName = "io.grpc.BindableService", type = MatchType.Interface)
public class BindableService_Instrumentation {
    public ServerServiceDefinition bindService() {
        ServerServiceDefinition returnValue = Weaver.callOriginal();

        String handler = this.getClass().getName();
        for (ServerMethodDefinition<?,?> serverMethod : returnValue.getMethods()) {
            MethodDescriptor<?, ?> methodDescriptor = serverMethod.getMethodDescriptor();
            String url = methodDescriptor.getFullMethodName();
            String methodType = methodDescriptor.getType().name();
            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(methodType, url, handler));
        }

        return returnValue;
    }
}
