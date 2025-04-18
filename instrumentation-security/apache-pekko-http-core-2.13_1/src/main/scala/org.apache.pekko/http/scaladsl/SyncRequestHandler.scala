package org.apache.pekko.http.scaladsl

import com.newrelic.api.agent.{NewRelic, Trace}
import org.apache.pekko.Done
import org.apache.pekko.http.scaladsl.model.{HttpEntity, HttpRequest, HttpResponse}
import org.apache.pekko.stream.Materializer
import org.apache.pekko.stream.scaladsl.Sink
import org.apache.pekko.stream.javadsl.Source
import org.apache.pekko.util.ByteString

import java.lang
import scala.concurrent.Future
import scala.runtime.AbstractFunction1

class SyncRequestHandler(handler: HttpRequest => HttpResponse)(implicit materializer: Materializer) extends AbstractFunction1[HttpRequest, HttpResponse] {

  @Trace(dispatcher = true)
  override def apply(param: HttpRequest): HttpResponse = {
    val body: lang.StringBuilder = new lang.StringBuilder();
    val dataBytes: Source[ByteString, AnyRef] = param.entity.getDataBytes()
    val isLockAcquired = PekkoCoreUtils.acquireServletLockIfPossible();

    if (!param.entity.isInstanceOf[HttpEntity.Chunked]) {
      val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
        val chunk = byteString.utf8String
        body.append(chunk)
      }
      val processingResult: Future[Done] = dataBytes.runWith(sink, materializer)
    }
    PekkoCoreUtils.preProcessHttpRequest(isLockAcquired, param, body, NewRelic.getAgent.getTransaction.getToken);
    val response: HttpResponse = handler.apply(param)
    ResponseFutureHelper.wrapResponseSync(response, materializer)
    response
  }
}
