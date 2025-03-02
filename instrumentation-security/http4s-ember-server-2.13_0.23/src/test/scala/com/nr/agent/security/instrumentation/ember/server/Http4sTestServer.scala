package com.nr.agent.security.instrumentation.ember.server

import cats.effect.{IO, Resource}
import com.comcast.ip4s._
import org.http4s.HttpApp
import org.http4s.server.Server
import org.http4s.ember.server.EmberServerBuilder
import cats.effect.unsafe.implicits.global

class Http4sTestServer(val testServerHost: String, val port: Int, val httpApp: HttpApp[IO]) {

  var server: Server = _
  var finalizer: IO[Unit] = _

  val serverResource: Resource[IO, Server] = EmberServerBuilder.default[IO]
                      .withHttpApp(httpApp)
                      .withHost(Host.fromString(testServerHost).orNull)
                      .withPort(Port.fromInt(port).get)
                      .build

  def start(): Unit = {
    val materializedServer = serverResource.allocated.unsafeRunSync()
    server = materializedServer._1
    finalizer = materializedServer._2
  }

  def stop(): Unit = finalizer.unsafeRunSync()

  def hostname: String = server.address.getHostName
}
