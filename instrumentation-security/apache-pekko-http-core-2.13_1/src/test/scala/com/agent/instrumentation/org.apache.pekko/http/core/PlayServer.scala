package com.agent.instrumentation.org.apache.pekko.http.core

import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.HttpMethods.GET
import org.apache.pekko.http.scaladsl.model.{HttpHeader, HttpRequest, HttpResponse, Uri}
import org.apache.pekko.stream.Materializer
import org.apache.pekko.stream.scaladsl.{Sink, Source}
import org.apache.pekko.util.Timeout

import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContextExecutor, Future}
import scala.language.postfixOps

//how play 2.6 sets up a server
class PlayServer {
  implicit val system: ActorSystem = ActorSystem()
  implicit val executor: ExecutionContextExecutor = system.dispatcher
  implicit val materializer: Materializer = Materializer.createMaterializer(system)
  implicit val timeout: Timeout = 3 seconds

  var bindingFuture: Future[Http.ServerBinding] = _
  var headers: Seq[HttpHeader] = Seq()

  def start(port: Int, async: Boolean): Unit = {

    if (async) {

      val asyncRequestHandler: HttpRequest => Future[HttpResponse] = {
        case HttpRequest(GET, Uri.Path("/asyncPing"), var1, _, _) => {
          headers = var1
          Future[HttpResponse](HttpResponse(entity = "Hoops!"))
        }
      }

      bindingFuture = Http().newServerAt("localhost", port).bind(asyncRequestHandler)

    }
    else {

      val requestHandler: HttpRequest => HttpResponse = {
        case HttpRequest(GET, Uri.Path("/ping"), var1, _, _) => {
          headers = var1
          HttpResponse(entity = "Hoops!")
        }
      }

      bindingFuture = Http().newServerAt("localhost", port).bindSync(requestHandler)
    }

    Await.ready({
      bindingFuture
    }, timeout.duration)
  }

  def stop(): Unit = {
    if (bindingFuture != null) {
      bindingFuture.flatMap(_.unbind()).onComplete(_ => {
        system.terminate()
      })
    }
  }

  def getHeaders: Seq[HttpHeader] = {
    headers
  }
}
