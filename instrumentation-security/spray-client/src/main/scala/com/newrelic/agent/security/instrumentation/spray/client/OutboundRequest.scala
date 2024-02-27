/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.spray.client

import spray.http.{HttpHeaders, HttpRequest}

/**
 * Spray's HttpRequest is immutable so we have to create a copy with the new headers.
 */

class OutboundRequest(request: HttpRequest) {
  private var req: HttpRequest = request

  def setHeader(key: String, value: String): Unit = {
    req = request.withHeaders(req.headers ++ List(HttpHeaders.RawHeader(key, value)))
  }
  def getRequest: HttpRequest = {
    req
  }
}