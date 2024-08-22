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
import com.newrelic.api.agent.security.NewRelicSecurity
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper
import com.newrelic.api.agent.security.schema.StringUtils
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException
import com.newrelic.api.agent.security.utils.logging.LogLevel
import com.newrelic.api.agent.{NewRelic, Token}

import java.lang
import scala.concurrent.{ExecutionContext, Future}

object ResponseFutureHelper {

  def wrapResponseAsync(token: Token, materializer: Materializer)(implicit ec: ExecutionContext): (HttpResponse) => Future[HttpResponse] = { response:HttpResponse => {
    Future {
      var updatedResponse: HttpResponse = response

      try {
        val stringResponse: lang.StringBuilder = new lang.StringBuilder();
        val dataBytes: Source[ByteString, _] = response.entity.getDataBytes()
        val isLockAquired = AkkaCoreUtils.acquireServletLockIfPossible();
        val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
          val chunk = byteString.utf8String
          stringResponse.append(chunk)
        }
        val processingResult: Future[Done] = dataBytes.runWith(sink, materializer)
        processingResult.onComplete {
         _ => {
           token.linkAndExpire()
           AkkaCoreUtils.postProcessHttpRequest(isLockAquired, stringResponse, response.entity.contentType.toString(), response.status.intValue(), this.getClass.getName, "apply", NewRelic.getAgent.getTransaction.getToken)
         }
        }

      } catch {
        case t: NewRelicSecurityException =>
          NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, AkkaCoreUtils.AKKA_HTTP_CORE_10_0_11, t.getMessage), t, classOf[AkkaCoreUtils].getName)
          throw t
        case _: Throwable =>
      }

      updatedResponse
    }
  }
  }

  def wrapResponseSync(httpResponse: HttpResponse, materializer: Materializer) {
    try {
      val stringResponse: lang.StringBuilder = new lang.StringBuilder();
      val dataBytes: Source[ByteString, _] = httpResponse.entity.getDataBytes()
      val isLockAquired = AkkaCoreUtils.acquireServletLockIfPossible();
      val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
        val chunk = byteString.utf8String
        stringResponse.append(chunk)
      }
      val processingResult: Future[Done] = dataBytes.runWith(sink, materializer)

      AkkaCoreUtils.postProcessHttpRequest(isLockAquired, stringResponse, httpResponse.entity.contentType.toString(), httpResponse.status.intValue(), this.getClass.getName, "apply", NewRelic.getAgent.getTransaction.getToken)
    } catch {
      case t: NewRelicSecurityException =>
        NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, AkkaCoreUtils.AKKA_HTTP_CORE_10_0_11, t.getMessage), t, classOf[AkkaCoreUtils].getName)
        throw t
      case _: Throwable =>
    }

    httpResponse
  }
}
