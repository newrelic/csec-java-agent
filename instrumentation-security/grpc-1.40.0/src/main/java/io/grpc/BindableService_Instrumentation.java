package io.grpc;

import com.newrelic.agent.security.instrumentation.grpc1400.GrpcUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(originalName = "io.grpc.BindableService", type = MatchType.Interface)
public class BindableService_Instrumentation {
    public ServerServiceDefinition bindService() {
        ServerServiceDefinition returnValue = Weaver.callOriginal();

        try {
            String handler = this.getClass().getName();
            for (ServerMethodDefinition<?, ?> serverMethod : returnValue.getMethods()) {
                MethodDescriptor<?, ?> methodDescriptor = serverMethod.getMethodDescriptor();
                String url = methodDescriptor.getFullMethodName();
                String methodType = methodDescriptor.getType().name();
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(methodType, url, handler));
            }
        } catch (Exception e){
            String message = "Instrumentation library: %s , error while getting app endpoints : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, GrpcUtils.GRPC_1_40_0, e.getMessage()), e, this.getClass().getName());
        }

        return returnValue;
    }
}
