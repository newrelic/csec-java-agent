package com.newrelic.agent.security.http4s.blaze.server

import cats.data.Kleisli
import cats.effect.Sync
import cats.implicits._
import com.newrelic.api.agent.security.NewRelicSecurity
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ICsecApiConstants, ServletHelper}
import com.newrelic.api.agent.security.schema._
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException
import com.newrelic.api.agent.security.schema.operation.RXSSOperation
import com.newrelic.api.agent.security.schema.policy.AgentPolicy
import com.newrelic.api.agent.security.utils.logging.LogLevel
import org.http4s.{Headers, Request, Response}

import java.util


object RequestProcessor {

  private val METHOD_WITH_HTTP_APP = "withHttpApp"
  private val HTTP_4S_EMBER_SERVER_2_12_0_23 = "HTTP4S-BLAZE-SERVER-2.12_0.21"
  private val X_FORWARDED_FOR = "x-forwarded-for"

  def genHttpApp[F[_] : Sync](httpApp: Kleisli[F, Request[F], Response[F]]): Kleisli[F, Request[F], Response[F]] = {
    Kleisli { req: Request[F] => nrRequestResponse(req, httpApp) }
  }

  private def nrRequestResponse[F[_] : Sync](request: Request[F], httpApp: Kleisli[F, Request[F], Response[F]]): F[Response[F]] = {
    val result = construct((): Unit)
      .redeemWith(_ => httpApp(request),
        _ => for {
          _ <- preprocessHttpRequest(request)
          resp <- httpApp(request)
          _ <- postProcessSecurityHook(resp)
        } yield resp
      )
    result
  }

  private def preprocessHttpRequest[F[_]: Sync](request: Request[F]): F[Unit] = construct {
    val isLockAcquired = BlazeUtils.acquireLockIfPossible()
    try {
      if (NewRelicSecurity.isHookProcessingActive && isLockAcquired && !NewRelicSecurity.getAgent.getSecurityMetaData.getRequest.isRequestParsed){

        val securityMetaData: SecurityMetaData = NewRelicSecurity.getAgent.getSecurityMetaData
        val securityRequest: HttpRequest = securityMetaData.getRequest
        val securityAgentMetaData: AgentMetaData = securityMetaData.getMetaData

        securityRequest.setMethod(request.method.name)
        securityRequest.setServerPort(request.serverPort.toInt)
        securityRequest.setClientIP(request.remoteAddr.get)
        securityRequest.setProtocol(BlazeUtils.getProtocol(request.isSecure.get))
        securityRequest.setUrl(request.uri.toString)

        if (securityRequest.getClientIP != null && securityRequest.getClientIP.trim.nonEmpty) {
          securityAgentMetaData.getIps.add(securityRequest.getClientIP)
          securityRequest.setClientPort(String.valueOf(request.remotePort.get))
        }

        processRequestHeaders(request.headers, securityRequest)
        securityMetaData.setTracingHeaderValue(BlazeUtils.getTraceHeader(securityRequest.getHeaders))
        securityRequest.setContentType(BlazeUtils.getContentType(securityRequest.getHeaders))

        // TODO extract request body & user class detection

        val trace: Array[StackTraceElement] = Thread.currentThread.getStackTrace
        securityMetaData.getMetaData.setServiceTrace(util.Arrays.copyOfRange(trace, 1, trace.length))
        securityRequest.setRequestParsed(true)
      }

    } catch {
      case e: Throwable => NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, HTTP_4S_EMBER_SERVER_2_12_0_23, e.getMessage), e, this.getClass.getName)
    } finally {
      if (isLockAcquired) {
        BlazeUtils.releaseLock()
      }
    }
  }

  private def processRequestHeaders(headers: Headers, securityRequest: HttpRequest): Unit = {
    headers.foreach(header => {
      var takeNextValue = false
      var headerKey: String = StringUtils.EMPTY
      if (header.name != null && header.name.isEmpty) {
        headerKey = header.name.toString
      }
      val headerValue: String = header.value

      val agentPolicy: AgentPolicy = NewRelicSecurity.getAgent.getCurrentPolicy
      val agentMetaData: AgentMetaData = NewRelicSecurity.getAgent.getSecurityMetaData.getMetaData
      if (agentPolicy != null
        && agentPolicy.getProtectionMode.getEnabled()
        && agentPolicy.getProtectionMode.getIpBlocking.getEnabled()
        && agentPolicy.getProtectionMode.getIpBlocking.getIpDetectViaXFF()
        && X_FORWARDED_FOR.equals(headerKey)) {
        takeNextValue = true
      } else if (ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID == headerKey) {
        // TODO: May think of removing this intermediate obj and directly create K2 Identifier.
        NewRelicSecurity.getAgent.getSecurityMetaData.setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(headerValue))
      }
      if (GenericHelper.CSEC_PARENT_ID == headerKey) {
        NewRelicSecurity.getAgent.getSecurityMetaData.addCustomAttribute(GenericHelper.CSEC_PARENT_ID, headerValue)
      }
      else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST == headerKey) {
        NewRelicSecurity.getAgent.getSecurityMetaData.addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true)
      }

      if (headerValue != null && headerValue.trim.nonEmpty) {
        if (takeNextValue) {
          agentMetaData.setClientDetectedFromXFF(true)
          securityRequest.setClientIP(headerValue)
          agentMetaData.getIps.add(securityRequest.getClientIP)
          securityRequest.setClientPort(StringUtils.EMPTY)
          takeNextValue = false
        }
      }
      securityRequest.getHeaders.put(headerKey.toLowerCase, headerValue)
    })
  }

  private def postProcessSecurityHook[F[_]: Sync](response: Response[F]): F[Unit] = construct {
    try {
      if (NewRelicSecurity.isHookProcessingActive) {
        val securityResponse = NewRelicSecurity.getAgent.getSecurityMetaData.getResponse
        securityResponse.setResponseCode(response.status.code)
        processResponseHeaders(response.headers, securityResponse)
        securityResponse.setResponseContentType(BlazeUtils.getContentType(securityResponse.getHeaders))

        // TODO extract response body
        ServletHelper.executeBeforeExitingTransaction()
        if (!ServletHelper.isResponseContentTypeExcluded(NewRelicSecurity.getAgent.getSecurityMetaData.getResponse.getResponseContentType)) {
          val rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent.getSecurityMetaData.getRequest, NewRelicSecurity.getAgent.getSecurityMetaData.getResponse, this.getClass.getName, METHOD_WITH_HTTP_APP)
          NewRelicSecurity.getAgent.registerOperation(rxssOperation)
        }
      }
    } catch {
      case e: Throwable =>
        if (e.isInstanceOf[NewRelicSecurityException]) {
          NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, HTTP_4S_EMBER_SERVER_2_12_0_23, e.getMessage), e, this.getClass.getName)
          throw e
        }
        NewRelicSecurity.getAgent.log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HTTP_4S_EMBER_SERVER_2_12_0_23, e.getMessage), e, this.getClass.getName)
        NewRelicSecurity.getAgent.reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HTTP_4S_EMBER_SERVER_2_12_0_23, e.getMessage), e, this.getClass.getName)
    }
  }

  private def processResponseHeaders(headers: Headers, securityResp: HttpResponse): Unit = {
    headers.foreach(header => {
      if (header.name != null && header.name.isEmpty) {
        securityResp.getHeaders.put(header.name.toString.toLowerCase, header.value)
      }
    })
  }

  private def construct[F[_]: Sync, T](t: => T): F[T] = Sync[F].delay(t)
}
