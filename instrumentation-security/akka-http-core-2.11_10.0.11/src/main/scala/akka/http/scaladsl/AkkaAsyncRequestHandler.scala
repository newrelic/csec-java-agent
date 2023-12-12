/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl

import akka.http.scaladsl.model.{HttpRequest, HttpResponse}
import akka.stream.Materializer
import com.newrelic.api.agent.Trace

import scala.concurrent.Future
import scala.runtime.AbstractFunction1

class AkkaAsyncRequestHandler(handler: HttpRequest ⇒ Future[HttpResponse])(implicit materializer: Materializer) extends AbstractFunction1[HttpRequest, Future[HttpResponse]] {

  @Trace
  override def apply(param: HttpRequest): Future[HttpResponse] = {

    var futureResponse: Future[HttpResponse] = null
    var body : StringBuilder = new StringBuilder();
//    param.entity.getDataBytes().runWith {
//      Sink.foreach[ByteString]((data) => body.append(data.utf8String))
//    };

    AkkaCoreUtils.preProcessHttpRequest(param, body.toString());
    futureResponse = handler.apply(param)
    futureResponse
  }
}
