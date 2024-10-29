package com.newrelic.agent.security.instrumentation.http4s.blaze

import cats.effect.{Async, Resource, Sync}
import com.newrelic.api.agent.security.NewRelicSecurity
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException
import com.newrelic.api.agent.security.schema.operation.SSRFOperation
import com.newrelic.api.agent.security.schema.{AbstractOperation, VulnerabilityCaseType}
import com.newrelic.api.agent.security.utils.logging.LogLevel
import org.http4s.Request
import org.http4s.client.Client

import java.net.URI

object NewrelicSecurityClientMiddleware {
  private final val nrSecCustomAttrName: String = "HTTP4S-BLAZE-CLIENT-OUTBOUND"
  private final val HTTP4S_BLAZE_CLIENT: String = "HTTP4S-BLAZE-CLIENT-2.12_0.22"

  private def construct[F[_] : Sync, T](t: T): F[T] = Sync[F].delay(t)

  private def clientResource[F[_] : Async](client: Client[F]): Client[F] =
    Client { req: Request[F] =>
      for {
        // pre-process hook
        operation <- Resource.eval(
          construct {
            val isLockAcquired = GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.HTTP_REQUEST, nrSecCustomAttrName)
            var operation: AbstractOperation = null
            if (isLockAcquired) {
              operation = preprocessSecurityHook(req)
            }
            operation
          })

        // TODO add Security Headers

        // original call
        response <- client.run(req)

        // post process and register exit event
        newRes <- Resource.eval(construct{
          val isLockAcquired = GenericHelper.isLockAcquired(nrSecCustomAttrName);
          if (isLockAcquired) {
            GenericHelper.releaseLock(nrSecCustomAttrName)
          }
          registerExitOperation(isLockAcquired, operation)
          response
        })

      } yield newRes
    }

  def resource[F[_] : Async](delegate: Resource[F, Client[F]]): Resource[F, Client[F]] = {
    val res: Resource[F, Client[F]] = delegate.map(c =>clientResource(c))
    res
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

