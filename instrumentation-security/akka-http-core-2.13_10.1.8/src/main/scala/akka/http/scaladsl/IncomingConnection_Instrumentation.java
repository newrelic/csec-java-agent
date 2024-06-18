/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl;

import akka.http.scaladsl.model.HttpRequest;
import akka.http.scaladsl.model.HttpResponse;
import akka.stream.Materializer;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import scala.Function1;
import scala.concurrent.Future;

@Weave(originalName = "akka.http.scaladsl.Http$IncomingConnection")
public class IncomingConnection_Instrumentation {

    public void handleWithSyncHandler(Function1<HttpRequest, HttpResponse> func, Materializer mat) {

        AkkaSyncRequestHandler wrapperHandler = new AkkaSyncRequestHandler(func, mat);
        func = wrapperHandler;

        Weaver.callOriginal();
    }

    public void handleWithAsyncHandler(Function1<HttpRequest, Future<HttpResponse>> func, int parallel, Materializer mat) {

        AkkaAsyncRequestHandler wrapperHandler = new AkkaAsyncRequestHandler(func, mat.executionContext(), mat);
        func = wrapperHandler;

        Weaver.callOriginal();
    }


}
