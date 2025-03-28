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
import akka.stream.scaladsl.{Source, _}
import akka.util.Timeout

import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContextExecutor, Future}
import scala.language.postfixOps

//how the akka http core docs' example sets up a server
class AkkaServer() {
  implicit val system: ActorSystem = ActorSystem()
  implicit val executor: ExecutionContextExecutor = system.dispatcher
  implicit val timeout: Timeout = 3 seconds

  var serverSource: Source[Http.IncomingConnection, Future[Http.ServerBinding]] = _
  var bindingFuture: Future[Http.ServerBinding] = _
  var headers: Seq[HttpHeader] = Seq()

  def start(port: Int, async: Boolean): Unit = {

    serverSource = Http().bind(interface = "localhost", port)

    if (async) {

      val asyncRequestHandler: HttpRequest => Future[HttpResponse] = {
        case HttpRequest(GET, Uri.Path("/asyncPing"), var1, _, _) => {
          headers = var1
          Future[HttpResponse](HttpResponse(entity = "Hoops!"))
        }
      }

      bindingFuture = serverSource.to(Sink.foreach {
        connection =>
          println("accepted connection from: " + connection.remoteAddress)
          connection handleWithAsyncHandler asyncRequestHandler
      }).run()
    }
    else {

      val requestHandler: HttpRequest => HttpResponse = {
        case HttpRequest(GET, Uri.Path("/ping"), var1, _, _) => {
          headers = var1
          HttpResponse(entity = "Hoops!")
        }
      }

      bindingFuture = serverSource.to(Sink.foreach {
        connection =>
          println("accepted connection from: " + connection.remoteAddress)
          connection handleWithSyncHandler requestHandler
      }).run()
    }

    Await.ready({
      bindingFuture
    }, timeout.duration)
  }

  def stop(): Unit = {
    if (bindingFuture != null) {
      bindingFuture.flatMap(_.unbind()).onComplete(_ => system.terminate())
    }
  }

  def getHeaders: Seq[HttpHeader] = {
    headers
  }
}
