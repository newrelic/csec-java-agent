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

import scala.concurrent.Future
import scala.runtime.AbstractFunction1

class AkkaSyncRequestHandler(handler: HttpRequest ⇒ HttpResponse)(implicit materializer: Materializer) extends AbstractFunction1[HttpRequest, HttpResponse] {

  @Trace(dispatcher = true)
  override def apply(param: HttpRequest): HttpResponse = {
    val body: StringBuilder = new StringBuilder();
    val dataBytes: Source[ByteString, AnyRef] = param.entity.getDataBytes()
    val isLockAquired = AkkaCoreUtils.acquireServletLockIfPossible();
    val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
      val chunk = byteString.utf8String
      body.append(chunk)
    }
    val processingResult: Future[Done] = dataBytes.runWith(sink, materializer)
    val response: HttpResponse = handler.apply(param)
    AkkaCoreUtils.preProcessHttpRequest(isLockAquired, param, body.toString(), NewRelic.getAgent.getTransaction.getToken);

    var updatedResponse: HttpResponse = response
    ResponseFutureHelper.wrapResponseSync(response, materializer)
    updatedResponse
  }
}
