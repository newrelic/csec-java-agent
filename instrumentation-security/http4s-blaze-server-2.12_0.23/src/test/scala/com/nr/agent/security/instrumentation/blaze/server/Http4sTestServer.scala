package com.nr.agent.security.instrumentation.blaze.server

import cats.effect.unsafe.implicits.global
import cats.effect.{IO, Resource}
import org.http4s.HttpApp
import org.http4s.blaze.server.BlazeServerBuilder
import org.http4s.server.Server

class Http4sTestServer(val testServerHost: String, val port: Int, val httpApp: HttpApp[IO]) {

  var server: Server = _
  var finalizer: IO[Unit] = _

  val serverResource: Resource[IO, Server] = BlazeServerBuilder[IO]
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
