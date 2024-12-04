package reactor.ipc.netty.http.server;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.reactivestreams.Publisher;

import java.util.function.Predicate;

@Weave(originalName = "reactor.ipc.netty.http.server.DefaultHttpServerRoutes$HttpRouteHandler")
final class HttpRouteHandler_Instrumentation {
    final Predicate<? super HttpServerRequest> condition = Weaver.callOriginal();

    public Publisher<Void> apply(HttpServerRequest request, HttpServerResponse response) {
        if (NewRelicSecurity.isHookProcessingActive()){
            HttpRequest securityRequest = NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
            if (condition instanceof HttpPredicate){
                securityRequest.setRoute(((HttpPredicate) condition).uri);
            } else {
                securityRequest.setRoute(URLMappingsHelper.WILDCARD);
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFramework(Framework.NETTY_REACTOR);
        }
        return Weaver.callOriginal();
    }
}
