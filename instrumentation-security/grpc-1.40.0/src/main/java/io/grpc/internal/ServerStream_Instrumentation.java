package io.grpc.internal;


import com.newrelic.api.agent.Token;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.grpc.Attributes;
import io.grpc.Metadata;
import io.grpc.Status;

// This class follows a request through the server side so we can hook in here to capture the outgoing request
@Weave(type = MatchType.Interface, originalName = "io.grpc.internal.ServerStream")
public abstract class ServerStream_Instrumentation {

    @NewField
    public Token tokenForCsec;

    @Trace(async = true)
    public void close(Status status, Metadata metadata) {
        Weaver.callOriginal();

        if (tokenForCsec != null) {
            tokenForCsec.expire();
            tokenForCsec = null;
        }
    }

    // server had an internal error
    @Trace(async = true)
    public void cancel(Status status) {
        Weaver.callOriginal();

        if (tokenForCsec != null) {
            tokenForCsec.expire();
            tokenForCsec = null;
        }
    }

    public abstract String getAuthority();

    public abstract Attributes getAttributes();
}
