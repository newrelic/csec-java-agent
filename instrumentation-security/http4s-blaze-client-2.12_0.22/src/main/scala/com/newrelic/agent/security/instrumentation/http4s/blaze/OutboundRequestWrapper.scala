package com.newrelic.agent.security.instrumentation.http4s.blaze

import org.http4s.{Header, Request}
import org.typelevel.ci.CIString

/**
 * Http4s's HttpRequest is immutable so we have to create a copy with the new headers.
 */

class OutboundRequest[F[_]](request: Request[F]) {
  private var req: Request[F] = request

  def setHeader(key: String, value: String): Unit = {
    req = req.withHeaders(req.headers.put(Header.Raw.apply(CIString.apply(key), value)))
  }
  def getRequest: Request[F] = {
    req
  }
}