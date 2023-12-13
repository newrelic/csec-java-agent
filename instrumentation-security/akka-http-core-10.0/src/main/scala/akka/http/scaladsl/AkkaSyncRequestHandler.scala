/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl

import akka.http.scaladsl.model.{HttpRequest, HttpResponse}
import akka.stream.Materializer
import akka.stream.javadsl.Source
import akka.stream.scaladsl.Sink
import akka.util.ByteString
import com.newrelic.api.agent.Trace

import scala.runtime.AbstractFunction1

class AkkaSyncRequestHandler(handler: HttpRequest ⇒ HttpResponse)(implicit materializer: Materializer) extends AbstractFunction1[HttpRequest, HttpResponse] {

  @Trace
  override def apply(param: HttpRequest): HttpResponse = {

    var body: StringBuilder = new StringBuilder();
    val dataBytes: Source[ByteString, _] = param.entity.getDataBytes()
    dataBytes.runWith(Sink.foreach[ByteString] { byteString =>
      val chunk = byteString.utf8String
      body.append(chunk)
    }, materializer)

    val isLockAcquired = AkkaCoreUtils.acquireServletLockIfPossible();
    AkkaCoreUtils.preProcessHttpRequest(isLockAcquired, param, body.toString());
    val response: HttpResponse = handler.apply(param)

    var updatedResponse: HttpResponse = response
    updatedResponse
  }
}
