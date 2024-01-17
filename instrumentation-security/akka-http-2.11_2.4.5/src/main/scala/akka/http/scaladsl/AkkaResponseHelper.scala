/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl

import akka.Done
import akka.http.scaladsl.model.{HttpEntity, HttpResponse}
import akka.http.scaladsl.server.AkkaCoreUtils
import akka.stream.Materializer
import akka.stream.javadsl.Source
import akka.stream.scaladsl.Sink
import akka.util.ByteString
import com.newrelic.api.agent.security.NewRelicSecurity
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException
import com.newrelic.api.agent.security.utils.logging.LogLevel
import com.newrelic.api.agent.{NewRelic, Token}

import java.lang
import scala.concurrent.{ExecutionContext, Future}
import scala.runtime.AbstractFunction1

class AkkaResponseHelper extends AbstractFunction1[HttpResponse, HttpResponse] {

  override def apply(httpResponse: HttpResponse): HttpResponse = {
    try {
      val stringResponse = new lang.StringBuilder()
      val isLockAquired = AkkaCoreUtils.acquireServletLockIfPossible()
      stringResponse.append(httpResponse.entity.asInstanceOf[HttpEntity.Strict].getData().decodeString("utf-8"))
      AkkaCoreUtils.postProcessHttpRequest(isLockAquired, stringResponse, httpResponse.entity.contentType.toString(), this.getClass.getName, "apply", NewRelic.getAgent.getTransaction.getToken())
    } catch {
      case t: NewRelicSecurityException =>
        NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, AkkaCoreUtils.AKKA_HTTP_2_4_5, t.getMessage), t, classOf[AkkaCoreUtils].getName)
        throw t
      case _: Throwable =>
    }

    httpResponse
  }
}
