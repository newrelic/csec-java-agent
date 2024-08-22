package io.vertx.core.http;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.VertxApiEndpointUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.vertx.core.Handler;


@Weave(originalName = "io.vertx.core.http.HttpServer", type = MatchType.Interface)
public class HttpServer_Instrumentation {

    public HttpServer_Instrumentation requestHandler(Handler<HttpServerRequest> handler){
        HttpServer_Instrumentation server = Weaver.callOriginal();
        try {
            VertxApiEndpointUtils.getInstance().generateAPIEndpoints(handler.hashCode());
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, "VERTX-CORE-3.4.0", e.getMessage()), e, VertxApiEndpointUtils.class.getName());
        }
        return server;
    }

}
