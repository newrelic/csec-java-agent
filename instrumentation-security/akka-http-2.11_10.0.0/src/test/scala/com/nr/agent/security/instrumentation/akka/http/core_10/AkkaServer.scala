package com.nr.agent.security.instrumentation.akka.http.core_10

import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.model._
import akka.http.scaladsl.model.headers.RawHeader
import akka.http.scaladsl.server.{Directives, RequestContext}
import akka.stream.ActorMaterializer
import akka.util.Timeout
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ServletHelper}

import scala.concurrent.duration._
import scala.concurrent.{ExecutionContextExecutor, Future}
import scala.language.postfixOps

//how the akka http core docs' example sets up a server
class AkkaServer extends Directives {
  implicit val system: ActorSystem = ActorSystem()
  implicit val executor: ExecutionContextExecutor = system.dispatcher
  implicit val materializer: ActorMaterializer = ActorMaterializer()
  implicit val timeout: Timeout = 3 seconds

  var serverSource: Future[Http.ServerBinding] = _
  var bindingFuture: Future[Http.ServerBinding] = _

  def start(port: Int): Unit = {
    val route = path(Segment) { segment =>
      get { ctx: RequestContext =>
        ctx.complete(
          HttpResponse.apply(entity = "Hello, World!",
            headers = (scala.collection.immutable.Seq(RawHeader.apply(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, segment),
              RawHeader.apply(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, segment),
              RawHeader.apply(GenericHelper.CSEC_PARENT_ID, segment)))))
      }
    }
    serverSource = Http().bindAndHandle(route, interface = "localhost", port)
    }

  def stop(): Unit = {
    if (serverSource != null) {
      serverSource.flatMap(_.unbind()).onComplete(_ => system.terminate())
    }
  }
}