package io.grpc;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.BaseClass, originalName = "io.grpc.Channel")
public class Channel_Instrumentation {

    public <RequestT, ResponseT> ClientCall_Instrumentation<RequestT, ResponseT> newCall(
            MethodDescriptor<RequestT, ResponseT> methodDescriptor, CallOptions callOptions) {
        ClientCall_Instrumentation<RequestT, ResponseT> result = Weaver.callOriginal();
        result.methodDescriptor = methodDescriptor;
        result.csecAuthority = authority();
        return result;
    }

    public String authority() {
        return Weaver.callOriginal();
    }
}
