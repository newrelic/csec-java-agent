package org.http4s.blaze.server;

import cats.data.Kleisli;
import cats.effect.kernel.Async;
import com.newrelic.agent.security.http4s.blaze.server.RequestProcessor$;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.http4s.Request;
import org.http4s.Response;

@Weave(originalName = "org.http4s.blaze.server.BlazeServerBuilder")
public class BlazeServerBuilder_Instrumentation<F> {

    private final Async<F> F = Weaver.callOriginal();

    public BlazeServerBuilder<F> withHttpApp(Kleisli<F, Request<F>, Response<F>> httpApp) {
        httpApp = RequestProcessor$.MODULE$.genHttpApp(httpApp, this.F);
        return Weaver.callOriginal();
    }
}
