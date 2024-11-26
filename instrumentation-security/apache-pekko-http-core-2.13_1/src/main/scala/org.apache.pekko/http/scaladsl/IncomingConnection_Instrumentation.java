package org.apache.pekko.http.scaladsl;

import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.pekko.http.scaladsl.model.HttpRequest;
import org.apache.pekko.http.scaladsl.model.HttpResponse;
import org.apache.pekko.stream.Materializer;
import scala.Function1;
import scala.concurrent.Future;

@Weave(originalName = "org.apache.pekko.http.scaladsl.Http$IncomingConnection")
public class IncomingConnection_Instrumentation {

    public void handleWithSyncHandler(Function1<HttpRequest, HttpResponse> func, Materializer mat) {
        SyncRequestHandler wrapperHandler = new SyncRequestHandler(func, mat);
        func = wrapperHandler;
        Weaver.callOriginal();
    }

    public void handleWithAsyncHandler(Function1<HttpRequest, Future<HttpResponse>> func, int parallel, Materializer mat) {
        AsyncRequestHandler wrapperHandler = new AsyncRequestHandler(func, mat.executionContext(), mat);
        func = wrapperHandler;
        Weaver.callOriginal();
    }
}
