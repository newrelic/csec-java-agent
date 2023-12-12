/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl

import akka.http.scaladsl.model.{HttpRequest, HttpResponse}
import com.newrelic.api.agent.Trace

import scala.runtime.AbstractFunction1

class AkkaSyncRequestHandler(handler: HttpRequest ⇒ HttpResponse) extends AbstractFunction1[HttpRequest, HttpResponse] {

  @Trace
  override def apply(param: HttpRequest): HttpResponse = {

    var body: StringBuilder = new StringBuilder();
    AkkaCoreUtils.preProcessHttpRequest(param, body.toString());
    val response: HttpResponse = handler.apply(param)

    var updatedResponse: HttpResponse = response
    updatedResponse
  }
}
