package com.nr.agent.security.instrumentation.spray.http

import akka.actor.{Actor, ActorContext, ActorRef, ActorSystem, Props}
import akka.io.IO
import akka.pattern._
import akka.util.Timeout
import org.junit.rules.ExternalResource
import spray.can.Http
import spray.routing.{HttpService, RequestContext, Route}

import scala.concurrent.duration._
import scala.concurrent.{Await, Future}
import scala.language.postfixOps

class HttpServer(port: Int) extends ExternalResource {
  private implicit val system: ActorSystem = ActorSystem()
  private implicit val timeout: Timeout = 3 seconds

  private val handler: ActorRef = system.actorOf(Props[MainActor], name = "handler")

  private def start(port: Int): Future[Any] = Await.ready(
    IO(Http) ? Http.Bind(handler, "localhost", port),
    timeout.duration
  )

  private def stop(): Unit = {
    IO(Http) ? Http.CloseAll
    system.stop(handler)
    system.shutdown()
  }
  override def before(): Unit = start(port)
  override def after(): Unit = stop()
}

object HttpServer {
  def apply(port: Int) = new HttpServer(port)
}

class MainActor extends Actor with HttpService {
  def route: Route = path("test") { (ctx: RequestContext) => ctx.complete("testing API")}
  def actorRefFactory: ActorContext = context
  def receive: Receive = runRoute(route)
}