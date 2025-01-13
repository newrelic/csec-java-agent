/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.akka.http.core_10

import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.model.HttpMethods._
import akka.http.scaladsl.model._
import akka.stream.ActorMaterializer
import akka.util.Timeout

import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContextExecutor, Future}
import scala.language.postfixOps

//how play 2.6 sets up a server
class PlayServer {
  implicit val system: ActorSystem = ActorSystem()
  implicit val executor: ExecutionContextExecutor = system.dispatcher
  implicit val materializer: ActorMaterializer = ActorMaterializer()
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

      bindingFuture = Http().bindAndHandleAsync(asyncRequestHandler, interface = "localhost", port)

    }
    else {

      val requestHandler: HttpRequest => HttpResponse = {
        case HttpRequest(GET, Uri.Path("/ping"), var1, _, _) => {
          headers = var1
          HttpResponse(entity = "Hoops!")
        }
      }

      bindingFuture = Http().bindAndHandleSync(requestHandler, interface = "localhost", port)
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
