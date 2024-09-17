package org.apache.pekko.http.scaladsl

import com.newrelic.agent.security.instrumentation.apache.pekko.PekkoCoreUtils
import com.newrelic.api.agent.security.NewRelicSecurity
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException
import com.newrelic.api.agent.security.utils.logging.LogLevel
import com.newrelic.api.agent.{NewRelic, Token}
import org.apache.pekko.Done
import org.apache.pekko.http.scaladsl.model.HttpResponse
import org.apache.pekko.stream.Materializer
import org.apache.pekko.stream.scaladsl.Sink
import org.apache.pekko.stream.javadsl.Source
import org.apache.pekko.util.ByteString

import java.lang
import scala.concurrent.{ExecutionContext, Future}

object ResponseFutureHelper {

  def wrapResponseAsync(token: Token, materializer: Materializer)(implicit ec: ExecutionContext): HttpResponse => Future[HttpResponse] = { response:HttpResponse => {
    Future {
      val updatedResponse: HttpResponse = response
      try {
        val stringResponse: lang.StringBuilder = new lang.StringBuilder();
        val dataBytes: Source[ByteString, _] = response.entity.getDataBytes()
        val isLockAcquired = PekkoCoreUtils.acquireServletLockIfPossible();
        val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
          val chunk = byteString.utf8String
          stringResponse.append(chunk)
        }
        val processingResult: Future[Done] = dataBytes.runWith(sink, materializer)
        processingResult.onComplete {
         _ => {
           token.linkAndExpire()
           PekkoCoreUtils.postProcessHttpRequest(isLockAcquired, stringResponse, response.entity.contentType.toString(),  response.status.intValue(), this.getClass.getName, "apply", NewRelic.getAgent.getTransaction.getToken)
         }
        }
      } catch {
        case t: NewRelicSecurityException =>
          NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, PekkoCoreUtils.PEKKO_HTTP_CORE_2_13_1, t.getMessage), t, classOf[PekkoCoreUtils].getName)
          throw t
        case _: Throwable =>
      }
      updatedResponse
    }
  }
  }

  def wrapResponseSync(httpResponse: HttpResponse, materializer: Materializer): Unit = {
    try {
      val stringResponse: lang.StringBuilder = new lang.StringBuilder();
      val dataBytes: Source[ByteString, _] = httpResponse.entity.getDataBytes()
      val isLockAcquired = PekkoCoreUtils.acquireServletLockIfPossible();
      val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
        val chunk = byteString.utf8String
        stringResponse.append(chunk)
      }
      val processingResult: Future[Done] = dataBytes.runWith(sink, materializer)

      PekkoCoreUtils.postProcessHttpRequest(isLockAcquired, stringResponse, httpResponse.entity.contentType.toString(),  httpResponse.status.intValue(), this.getClass.getName, "apply", NewRelic.getAgent.getTransaction.getToken())
    } catch {
      case t: NewRelicSecurityException =>
        NewRelicSecurity.getAgent.log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, PekkoCoreUtils.PEKKO_HTTP_CORE_2_13_1, t.getMessage), t, classOf[PekkoCoreUtils].getName)
        throw t
      case _: Throwable =>
    }
  }
}
