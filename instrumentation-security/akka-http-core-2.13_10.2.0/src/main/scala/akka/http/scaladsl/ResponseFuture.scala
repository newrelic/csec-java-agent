/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl

import akka.Done
import akka.http.scaladsl.model.HttpResponse
import akka.stream.Materializer
import akka.stream.javadsl.Source
import akka.stream.scaladsl.Sink
import akka.util.ByteString
import com.newrelic.api.agent.Transaction
import com.newrelic.api.agent.security.schema.StringUtils
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException
import com.newrelic.api.agent.weaver.Weaver

import java.util.concurrent.TimeUnit
import scala.concurrent.duration.FiniteDuration
import scala.concurrent.{ExecutionContext, Future}

object ResponseFuture {

  def wrapResponseAsync(materializer: Materializer)(implicit ec: ExecutionContext): (HttpResponse) => Future[HttpResponse] = { response:HttpResponse => {
    Future {
      var updatedResponse: HttpResponse = response

      try {
        val stringResponse: StringBuilder = new StringBuilder();
        val dataBytes: Source[ByteString, _] = response.entity.getDataBytes()
        val isLockAquired = AkkaCoreUtils.acquireServletLockIfPossible();
        val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
          val chunk = byteString.utf8String
          stringResponse.append(chunk)
        }
        val processingResult: Future[Done] = dataBytes.runWith(sink, materializer)
        var contentType = ""
        response.headers.foreach( header => {
          if(StringUtils.equalsAny(header.name(), "contenttype", "content-type")){
            contentType = header.value()
          }
        })

        AkkaCoreUtils.postProcessHttpRequest(isLockAquired, stringResponse.toString(), contentType, this.getClass.getName, "apply")
      } catch {
        case t: NewRelicSecurityException =>
          t.printStackTrace()
          throw t
        case _: Throwable =>
      }

      updatedResponse
    }
  }
  }

  def wrapResponseSync(httpResponse: HttpResponse, materializer: Materializer) {
    try {
      val stringResponse: StringBuilder = new StringBuilder();
      val dataBytes: Source[ByteString, _] = httpResponse.entity.getDataBytes()
      val isLockAquired = AkkaCoreUtils.acquireServletLockIfPossible();
      val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
        val chunk = byteString.utf8String
        stringResponse.append(chunk)
      }
      val processingResult: Future[Done] = dataBytes.runWith(sink, materializer)
      var contentType = ""
      httpResponse.headers.foreach(header => {
        if (StringUtils.equalsAny(header.name(), "contenttype", "content-type")) {
          contentType = header.value()
        }
      })

      AkkaCoreUtils.postProcessHttpRequest(isLockAquired, stringResponse.toString(), contentType, this.getClass.getName, "apply")
    } catch {
      case t: NewRelicSecurityException =>
        t.printStackTrace()
        throw t
      case _: Throwable =>
    }

    httpResponse
  }
}
