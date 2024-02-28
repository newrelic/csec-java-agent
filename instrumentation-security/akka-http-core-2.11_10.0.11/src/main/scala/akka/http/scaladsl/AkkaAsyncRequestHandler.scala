/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl

import akka.Done
import akka.http.scaladsl.model.{HttpRequest, HttpResponse}
import akka.stream.Materializer
import akka.stream.javadsl.Source
import akka.stream.scaladsl.Sink
import akka.util.ByteString
import com.newrelic.api.agent.{NewRelic, Trace}

import java.lang
import scala.concurrent.{ExecutionContext, Future}
import scala.runtime.AbstractFunction1

class AkkaAsyncRequestHandler(handler: HttpRequest ⇒ Future[HttpResponse])(implicit ec: ExecutionContext, materializer: Materializer) extends AbstractFunction1[HttpRequest, Future[HttpResponse]] {

  @Trace(dispatcher = true)
  override def apply(param: HttpRequest): Future[HttpResponse] = {
    val body: lang.StringBuilder = new lang.StringBuilder();
    val dataBytes: Source[ByteString, AnyRef] = param.entity.getDataBytes()
    val isLockAquired = AkkaCoreUtils.acquireServletLockIfPossible();
    val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
      val chunk = byteString.utf8String
      body.append(chunk)
    }
    val processingResult: Future[Done] = dataBytes.runWith(sink, materializer)
    AkkaCoreUtils.preProcessHttpRequest(isLockAquired, param, body, NewRelic.getAgent.getTransaction.getToken);
    val futureResponse: Future[HttpResponse] = handler.apply(param)
    futureResponse.flatMap(ResponseFutureHelper.wrapResponseAsync(NewRelic.getAgent.getTransaction.getToken, materializer))
    futureResponse
  }
}
