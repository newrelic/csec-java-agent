/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.agent.instrumentation.akka.http.core_10

import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.model.{HttpHeader, HttpRequest, HttpResponse}
import akka.stream.ActorMaterializer
import com.agent.instrumentation.akka.http.core_211_10011.{AkkaServer, PlayServer}
import com.newrelic.agent.security.introspec.{InstrumentationTestConfig, SecurityInstrumentationTestRunner, SecurityIntrospector}
import com.newrelic.api.agent.Trace
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType
import com.newrelic.api.agent.security.schema.operation.SSRFOperation
import com.nr.agent.security.akka.core.AkkaCoreUtils
import org.junit.runner.RunWith
import org.junit.{After, Assert, Test}

import java.net.ServerSocket
import java.util.UUID
import scala.concurrent.duration.DurationInt
import scala.concurrent.{Await, Future}

@RunWith(classOf[SecurityInstrumentationTestRunner])
@InstrumentationTestConfig(includePrefixes = Array("akka"))
class AkkaHttpCoreTest {

  implicit val system: ActorSystem = ActorSystem()
  implicit val materializer: ActorMaterializer = ActorMaterializer()

  val akkaServer = new AkkaServer()
  val playServer = new PlayServer()
  var port: Int = getRandomPort
  val baseUrl: String = "http://localhost:" + port


  def startAkkaSync(): Unit = {
    akkaServer.start(port, async = false)
  }

  def startAkkaAsync(): Unit = {
    akkaServer.start(port, async = true)
  }

  def startPlaySync(): Unit = {
    playServer.start(port, async = false)
  }

  def startPlayAsync(): Unit = {
    playServer.start(port, async = true)
  }

  @After
  def stop(): Unit = {
    akkaServer.stop()
    playServer.stop()
  }

  @Test
  def syncHandlerAkkaServerTestWithAkkaServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(headerValue)
    introspector.setK2TracingData(headerValue)

    startAkkaSync()
    Await.result(makeHttpRequest(false), new DurationInt(10).seconds)
    val headers: Seq[HttpHeader] = akkaServer.getHeders()

    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    val operations: SSRFOperation = introspector.getOperations.get(0).asInstanceOf[SSRFOperation]
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operations.getCaseType)
    Assert.assertEquals("Invalid executed method name.", AkkaCoreUtils.METHOD_SINGLE_REQUEST_IMPL, operations.getMethodName)
    Assert.assertEquals("Invalid executed parameters.", baseUrl + "/ping", operations.getArg)
    Assert.assertEquals("Invalid protocol.", introspector.getSecurityMetaData.getRequest.getProtocol, "http")
    Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.exists(header => header.name().contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)))
    Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.exists(header => header.name().contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER)))
    for (header <- headers) {
      if(header.name().contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)) {
        Assert.assertEquals(String.format("Invalid K2 header value for: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue, header.value())
      }
      if (header.name().contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER)) {
        Assert.assertEquals(String.format("Invalid K2 header value for: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;", headerValue), header.value())
      }
    }
  }

  @Test
  def asyncHandlerAkkaServerTestWithAkkaServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(headerValue)
    introspector.setK2TracingData(headerValue)

    startAkkaAsync()
    Await.result(makeHttpRequest(true), new DurationInt(10).seconds)
    val headers: Seq[HttpHeader] = akkaServer.getHeders()

    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    val operations: SSRFOperation = introspector.getOperations.get(0).asInstanceOf[SSRFOperation]
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operations.getCaseType)
    Assert.assertEquals("Invalid executed method name.", AkkaCoreUtils.METHOD_SINGLE_REQUEST_IMPL, operations.getMethodName)
    Assert.assertEquals("Invalid executed parameters.", baseUrl + "/asyncPing", operations.getArg)
    Assert.assertEquals("Invalid protocol.", introspector.getSecurityMetaData.getRequest.getProtocol, "http")
    Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.exists(header => header.name().contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)))
    Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.exists(header => header.name().contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER)))
    for (header <- headers) {
      if (header.name().contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)) {
        Assert.assertEquals(String.format("Invalid K2 header value for: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue, header.value())
      }
      if (header.name().contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER)) {
        Assert.assertEquals(String.format("Invalid K2 header value for: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;", headerValue), header.value())
      }
    }
  }

  @Test
  def syncHandlerAkkaServerTestWithPlayServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(headerValue)
    introspector.setK2TracingData(headerValue)

    startPlaySync()
    Await.result(makeHttpRequest(false), new DurationInt(10).seconds)
    val headers: Seq[HttpHeader] = playServer.getHeders()

    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    val operations: SSRFOperation = introspector.getOperations.get(0).asInstanceOf[SSRFOperation]
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operations.getCaseType)
    Assert.assertEquals("Invalid executed method name.", AkkaCoreUtils.METHOD_SINGLE_REQUEST_IMPL, operations.getMethodName)
    Assert.assertEquals("Invalid executed parameters.", baseUrl + "/ping", operations.getArg)
    Assert.assertEquals("Invalid protocol.", introspector.getSecurityMetaData.getRequest.getProtocol, "http")
    Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.exists(header => header.name().contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)))
    Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.exists(header => header.name().contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER)))
    for (header <- headers) {
      if (header.name().contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)) {
        Assert.assertEquals(String.format("Invalid K2 header value for: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue, header.value())
      }
      if (header.name().contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER)) {
        Assert.assertEquals(String.format("Invalid K2 header value for: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;", headerValue), header.value())
      }
    }
  }

  @Test
  def asyncHandlerAkkaServerTestWithPlayServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(headerValue)
    introspector.setK2TracingData(headerValue)

    startPlayAsync()
    Await.result(makeHttpRequest(true), new DurationInt(10).seconds)
    val headers: Seq[HttpHeader] = playServer.getHeders()

    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    val operations: SSRFOperation = introspector.getOperations.get(0).asInstanceOf[SSRFOperation]
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operations.getCaseType)
    Assert.assertEquals("Invalid executed method name.", AkkaCoreUtils.METHOD_SINGLE_REQUEST_IMPL, operations.getMethodName)
    Assert.assertEquals("Invalid executed parameters.", baseUrl + "/asyncPing", operations.getArg)
    Assert.assertEquals("Invalid protocol.", introspector.getSecurityMetaData.getRequest.getProtocol, "http")
    Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.exists(header => header.name().contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)))
    Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.exists(header => header.name().contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER)))
    for (header <- headers) {
      if (header.name().contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)) {
        Assert.assertEquals(String.format("Invalid K2 header value for: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue, header.value())
      }
      if (header.name().contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER)) {
        Assert.assertEquals(String.format("Invalid K2 header value for: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;", headerValue), header.value())
      }
    }
  }

  @Trace(dispatcher = true, nameTransaction = true)
  private def makeHttpRequest(async: Boolean): Future[HttpResponse] = {
    Http().singleRequest(HttpRequest(uri = baseUrl + (if (async) "/asyncPing" else "/ping")))
  }

  def getRandomPort: Int = {
    var port: Int = 0

    try {
      val socket: ServerSocket = new ServerSocket(0)
      port = socket.getLocalPort
      socket.close()
    } catch {
      case e: Exception =>
        throw new RuntimeException("Unable to allocate ephemeral port")
    }
    port
  }
}
