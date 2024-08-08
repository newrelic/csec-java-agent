package reactor.ipc.netty.http.server;

import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.reactivestreams.Publisher;

import java.util.function.Predicate;

@Weave(originalName = "reactor.ipc.netty.http.server.DefaultHttpServerRoutes$HttpRouteHandler")
final class HttpRouteHandler_Instrumentation {
    final Predicate<? super HttpServerRequest> condition = Weaver.callOriginal();
    public Publisher<Void> apply(HttpServerRequest request, HttpServerResponse response) {
        // TODO: Calculate route for endpoints
        return Weaver.callOriginal();
    }
}
