/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl.server

import akka.Done
import akka.stream.javadsl.Source
import akka.stream.scaladsl.Sink
import akka.util.ByteString

import java.util.concurrent.atomic.AtomicBoolean
import java.util.logging.Level
import com.newrelic.api.agent.{NewRelic, Trace}
import com.newrelic.api.agent.security.NewRelicSecurity
import com.newrelic.api.agent.security.utils.logging.LogLevel

import java.lang
import scala.collection.mutable
import scala.concurrent.Future
import scala.runtime.AbstractFunction1

object CsecAkkaHttpContextFunction {

  final val retransformed = new AtomicBoolean(false)

  def contextWrapper(original: Function1[RequestContext, Future[RouteResult]]): Function1[RequestContext, Future[RouteResult]] = {
    if (retransformed.compareAndSet(false, true)) {
      NewRelicSecurity.getAgent.log(LogLevel.FINER, "Retransforming akka.http.scaladsl.server.AkkaHttpContextFunction", this.getClass.getName);
      try {
        val agentBridgeClass = Class.forName("com.newrelic.agent.bridge.AgentBridge")
        val instrumentation = agentBridgeClass.getDeclaredField("instrumentation")
        val instrumentationObject = instrumentation.get(null)
        val instrumentationInterface = Class.forName("com.newrelic.agent.bridge.Instrumentation")
        val retransformUninstrumentedClassMethod = instrumentationInterface.getDeclaredMethod("retransformUninstrumentedClass", classOf[Class[_]])
        retransformUninstrumentedClassMethod.invoke(instrumentationObject, classOf[ContextWrapper])
      } catch {
        case e: Throwable =>
          NewRelic.getAgent.getLogger.log(Level.SEVERE, "Unable to instrument akka.http.scaladsl.server.AkkaHttpContextFunction [akka-http-2.11_2.4.5] due to error", e)
      }
      NewRelicSecurity.getAgent.log(LogLevel.FINER, "Retransformed akka.http.scaladsl.server.AkkaHttpContextFunction", this.getClass.getName);
    }

    new ContextWrapper(original)
  }

}

class ContextWrapper(original: Function1[RequestContext, Future[RouteResult]]) extends AbstractFunction1[RequestContext, Future[RouteResult]] {

  @Trace(dispatcher = true)
  override def apply(ctx: RequestContext): Future[RouteResult] = {
    try {

      var httpRequest = ctx.request;
      val body: lang.StringBuilder = new lang.StringBuilder();
      val dataBytes: Source[ByteString, AnyRef] = httpRequest.entity.getDataBytes()
      val isLockAquired = AkkaCoreUtils.acquireServletLockIfPossible();
      val sink: Sink[ByteString, Future[Done]] = Sink.foreach[ByteString] { byteString =>
        val chunk = byteString.utf8String
        body.append(chunk)
      }
      val processingResult: Future[Done] = dataBytes.runWith(sink, ctx.materializer)
      AkkaCoreUtils.preProcessHttpRequest(isLockAquired, httpRequest, body, NewRelic.getAgent.getTransaction.getToken);
      original.apply(ctx)
    } catch {
      case t: Throwable => {
        original.apply(ctx)
      }
    }
  }

  override def compose[A](g: (A) => RequestContext): (A) => Future[RouteResult] = original.compose(g)

  override def andThen[A](g: (Future[RouteResult]) => A): (RequestContext) => A = original.andThen(g)

  override def toString(): String = original.toString()

}
