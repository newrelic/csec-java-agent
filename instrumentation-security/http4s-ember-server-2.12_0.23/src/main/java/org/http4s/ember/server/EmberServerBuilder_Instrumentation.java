package org.http4s.ember.server;

import cats.data.Kleisli;
import cats.effect.kernel.Async;
import com.newrelic.agent.security.http4s.ember.server.RequestProcessor$;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.http4s.Request;
import org.http4s.Response;

@Weave(originalName = "org.http4s.ember.server.EmberServerBuilder")
public class EmberServerBuilder_Instrumentation<F> {

    public final Async<F> org$http4s$ember$server$EmberServerBuilder$$evidence$1 = Weaver.callOriginal();

    public EmberServerBuilder_Instrumentation<F> withHttpApp(Kleisli<F, Request<F>, Response<F>> httpApp) {
        httpApp = RequestProcessor$.MODULE$.genHttpApp(httpApp, this.org$http4s$ember$server$EmberServerBuilder$$evidence$1);
        return Weaver.callOriginal();
    }
}
