package com.newrelic.agent.security.instrumentation.http4s.blaze

import cats.effect.{Async, ConcurrentEffect, Resource, Sync}
import com.newrelic.api.agent.security.NewRelicSecurity
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ServletHelper}
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException
import com.newrelic.api.agent.security.schema.operation.SSRFOperation
import com.newrelic.api.agent.security.schema.{AbstractOperation, StringUtils, VulnerabilityCaseType}
import com.newrelic.api.agent.security.utils.SSRFUtils
import com.newrelic.api.agent.security.utils.logging.LogLevel
import org.http4s.Request
import org.http4s.client.Client

import java.net.URI

object NewrelicSecurityClientMiddleware {
  private final val nrSecCustomAttrName: String = "HTTP4S-BLAZE-CLIENT-OUTBOUND"
  private final val HTTP4S_BLAZE_CLIENT: String = "HTTP4S-BLAZE-CLIENT-2.12_0.21"

  private def construct[F[_] : Sync, T](t: T): F[T] = Sync[F].delay(t)

  private def clientResource[F[_] : ConcurrentEffect](client: Client[F]): Client[F] =
    Client { req: Request[F] =>
      for {
        // pre-process hook
        operation <- Resource.liftF(construct {
            val isLockAcquired = GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST, nrSecCustomAttrName)
            var operation: AbstractOperation = null
            if (isLockAcquired) {
              operation = preprocessSecurityHook(req)
            }
            operation
          })

        request <- Resource.liftF(construct {addSecurityHeaders(req, operation)})

        // original call
        response <- client.run(request)

        // post process and register exit event
        newRes <- Resource.liftF(construct{
          val isLockAcquired = GenericHelper.isLockAcquired(nrSecCustomAttrName);
          if (isLockAcquired) {
            GenericHelper.releaseLock(nrSecCustomAttrName)
          }
          registerExitOperation(isLockAcquired, operation)
          response
        })

      } yield newRes
    }

  def resource[F[_] : ConcurrentEffect](delegate: Resource[F, Client[F]]): Resource[F, Client[F]] = {
    val res: Resource[F, Client[F]] = delegate.map(c =>clientResource(c))
    res
  }

  private def addSecurityHeaders[F[_] : Async](request: Request[F], operation: AbstractOperation): Request[F] = {
    val outboundRequest = new OutboundRequest(request)
    if (operation != null) {
      val securityMetaData = NewRelicSecurity.getAgent.getSecurityMetaData
      val iastHeader = NewRelicSecurity.getAgent.getSecurityMetaData.getFuzzRequestIdentifier.getRaw
      if (iastHeader != null && iastHeader.trim.nonEmpty) {
        outboundRequest.setHeader(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader)
      }
      val csecParentId = securityMetaData.getCustomAttribute(GenericHelper.CSEC_PARENT_ID, classOf[String])
      if (StringUtils.isNotBlank(csecParentId)) {
        outboundRequest.setHeader(GenericHelper.CSEC_PARENT_ID, csecParentId)
      }
      try {
        NewRelicSecurity.getAgent.getSecurityMetaData.getMetaData.setFromJumpRequiredInStackTrace(Integer.valueOf(4))
        NewRelicSecurity.getAgent.registerOperation(operation)
      }
      finally {
        if (operation.getApiID != null && operation.getApiID.trim.nonEmpty && operation.getExecutionId != null && operation.getExecutionId.trim.nonEmpty) {
          outboundRequest.setHeader(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue, operation.getApiID, operation.getExecutionId, NewRelicSecurity.getAgent.getAgentUUID))
        }
      }
    }
    outboundRequest.getRequest
  }


  private def preprocessSecurityHook[F[_] : Async](httpRequest: Request[F]): AbstractOperation = {
    try {
      val securityMetaData = NewRelicSecurity.getAgent.getSecurityMetaData
      if (!NewRelicSecurity.isHookProcessingActive || securityMetaData.getRequest.isEmpty) return null
      // Generate required URL
      var methodURI: URI = null
      var uri: String = null
      try {
        methodURI = new URI(httpRequest.uri.toString)
        uri = methodURI.toString
        if (methodURI == null) return null
      } catch {
        case ignored: Exception =>
          NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, HTTP4S_BLAZE_CLIENT, ignored.getMessage), ignored, this.getClass.getName)
          return null
      }
      return new SSRFOperation(uri, this.getClass.getName, "run")
    } catch {
      case e: Throwable =>
        if (e.isInstanceOf[NewRelicSecurityException]) {
          NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, HTTP4S_BLAZE_CLIENT, e.getMessage), e, this.getClass.getName)
          throw e
        }
        NewRelicSecurity.getAgent.log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HTTP4S_BLAZE_CLIENT, e.getMessage), e, this.getClass.getName)
        NewRelicSecurity.getAgent.reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HTTP4S_BLAZE_CLIENT, e.getMessage), e, this.getClass.getName)
    }
    null
  }

  private def registerExitOperation(isProcessingAllowed: Boolean, operation: AbstractOperation): Unit = {
    try {
      if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive || NewRelicSecurity.getAgent.getSecurityMetaData.getRequest.isEmpty) return
      NewRelicSecurity.getAgent.registerExitEvent(operation)
    } catch {
      case e: Throwable =>
        NewRelicSecurity.getAgent.log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, HTTP4S_BLAZE_CLIENT, e.getMessage), e, this.getClass.getName)
    }
  }
}

