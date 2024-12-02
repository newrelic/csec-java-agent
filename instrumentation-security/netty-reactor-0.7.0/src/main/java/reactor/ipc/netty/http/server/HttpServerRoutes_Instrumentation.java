package reactor.ipc.netty.http.server;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.reactivestreams.Publisher;
import java.util.function.BiFunction;
import java.util.function.Predicate;

@Weave(originalName = "reactor.ipc.netty.http.server.HttpServerRoutes", type = MatchType.Interface)
public class HttpServerRoutes_Instrumentation {

    public HttpServerRoutes_Instrumentation route( Predicate<? super HttpServerRequest> condition, BiFunction<? super HttpServerRequest, ? super HttpServerResponse, ? extends Publisher<Void>> handler) {
        HttpServerRoutes_Instrumentation result = Weaver.callOriginal();
        addURLMapping(condition, handler.getClass().getName());
        return result;
    }
    private void addURLMapping(Predicate<? super HttpServerRequest> condition, String className){
        try {
            if (!NewRelicSecurity.getAgent().isSecurityEnabled()) {
                return;
            }
            className = StringUtils.substringBefore(className, URLMappingsHelper.SEPARATOR);
            ApplicationURLMapping mapping;
            if (condition instanceof HttpPredicate){
                HttpPredicate endpoint = (HttpPredicate) condition;
                mapping = new ApplicationURLMapping(endpoint.method.name(), endpoint.uri, className);
            } else {
                mapping = new ApplicationURLMapping(URLMappingsHelper.WILDCARD, URLMappingsHelper.WILDCARD, className);
            }
            URLMappingsHelper.addApplicationURLMapping(mapping);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, "NETTY-REACTOR-0.7.0", e.getMessage()), e, this.getClass().getName());
        }
    }
}
