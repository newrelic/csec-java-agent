package com.newrelic.agent.security.http4s.ember.server

import cats.data.Kleisli
import cats.effect.Sync
import cats.implicits._
import com.comcast.ip4s.Port
import com.newrelic.api.agent.{NewRelic}
import com.newrelic.api.agent.security.NewRelicSecurity
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ServletHelper}
import com.newrelic.api.agent.security.schema.{AgentMetaData, HttpRequest, SecurityMetaData, StringUtils}
import com.newrelic.api.agent.security.utils.logging.LogLevel
import org.http4s.{Request, Response}

import java.util


object RequestProcessor{
  private val METHOD_WITH_HTTP_APP = "withHttpApp"
  private val NR_SEC_CUSTOM_ATTRIB_NAME = "HTTP4S_EMBER_SERVER_LOCK-"
  private val HTTP_4S_EMBER_SERVER_2_13_0_23 = "HTTP4S-EMBER-SERVER-2.13_0.23"
  private val X_FORWARDED_FOR = "x-forwarded-for"
  private val QUESTION_MARK = "?"

  def processHttpApp[F[_] : Sync](httpApp: Kleisli[F, Request[F], Response[F]]): Kleisli[F, Request[F], Response[F]] = {
    Kleisli { req: Request[F] => nrRequestResponse(req, httpApp) }
  }

  def nrRequestResponse[F[_] : Sync](request: Request[F], httpApp: Kleisli[F, Request[F], Response[F]]): F[Response[F]] = {
    val result = construct((): Unit)
      .redeemWith(_ => httpApp(request),
        _ => for {
          _ <- processReq(request)
          resp <- httpApp(request)
        } yield resp
      )
    result
  }

  def processReq[F[_]: Sync](request: Request[F]): F[Unit] = construct {
    println("CSEC : Instrumentation active (false in case of NoOp-Transaction) : " + NewRelicSecurity.isHookProcessingActive)
    println("CSEC : Instance of NR Transaction : " + NewRelic.getAgent.getTransaction.getClass)
    preProcessHttpRequest(true, request)
  }
  private def construct[F[_]: Sync, T](t: => T): F[T] = Sync[F].delay(t)

  private def preProcessHttpRequest[F[_]: Sync](isServletLockAcquired: Boolean, request: Request[F]): Unit = {
    if (!(isServletLockAcquired)) {
      return
    }
    try {
      if (!NewRelicSecurity.isHookProcessingActive) {
        return
      }
      val securityMetaData: SecurityMetaData = NewRelicSecurity.getAgent.getSecurityMetaData
      val securityRequest: HttpRequest = securityMetaData.getRequest
      if (securityRequest.isRequestParsed) {
        return
      }
      val securityAgentMetaData: AgentMetaData = securityMetaData.getMetaData
      securityRequest.setMethod(request.method.name)
      securityRequest.setClientPort(request.remotePort.get.toString)
      //TODO Client IP extraction is pending

      securityRequest.setServerPort(((request.serverPort).get.asInstanceOf[Port]).value)
      // TODO Process HTTP Request Headers
      securityMetaData.setTracingHeaderValue(getTraceHeader(securityRequest.getHeaders))
      securityRequest.setProtocol(getProtocol(request.isSecure.get))
      securityRequest.setUrl(request.uri.toString)

      // TODO extract request body
      // TODO user class detection

      securityRequest.setRequestParsed(true)
    } catch {
      case ignored => ignored.printStackTrace()
        NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, HTTP_4S_EMBER_SERVER_2_13_0_23, ignored.getMessage), ignored, this.getClass.getName)
    } finally {
    }
  }

  private def getTraceHeader(headers: util.Map[String, String]): String = {
    var data: String = StringUtils.EMPTY
    if (headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER) || headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase)) {
      data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER)
      if (data == null || data.trim.isEmpty) data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase)
    }
    data
  }

  private def getProtocol(isSecure: Boolean): String = {
    if (isSecure) "https"
    else "http"
  }
}
