package com.nr.agent.security.instrumentation.blaze.server

import scala.concurrent.ExecutionContext.global
import cats.effect.{ConcurrentEffect, ContextShift, IO, Resource, Timer}
import org.http4s.HttpApp
import org.http4s.server.blaze.BlazeServerBuilder
import org.http4s.server.Server

import scala.concurrent.ExecutionContext

class Http4sTestServer(val testServerHost: String, val port: Int, val httpApp: HttpApp[IO]) {

  var server: Server[IO] = _
  var finalizer: IO[Unit] = _

  implicit val cs: ContextShift[IO] = IO.contextShift(global)
  implicit val timer: Timer[IO] = IO.timer(global)
  implicit val concurrentEffect: ConcurrentEffect[IO] = IO.ioConcurrentEffect

  implicit val ec: ExecutionContext = global

  val serverResource: Resource[IO, Server[IO]] = BlazeServerBuilder.apply(global)
    .withHttpApp(httpApp)
    .bindHttp(port, testServerHost)
    .resource

  def start(): Unit = {
    val materializedServer = serverResource.allocated.unsafeRunSync()
    server = materializedServer._1
    finalizer = materializedServer._2
  }

  def stop(): Unit = finalizer.unsafeRunSync()

  def hostname: String = server.address.getHostName
}
