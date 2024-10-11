package com.agent.instrumentation.org.apache.pekko.http.core

import com.newrelic.agent.security.introspec.{InstrumentationTestConfig, SecurityInstrumentationTestRunner, SecurityIntrospector}
import com.newrelic.api.agent.Trace
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ServletHelper}
import com.newrelic.api.agent.security.schema.operation.{RXSSOperation, SSRFOperation}
import com.newrelic.api.agent.security.schema.{SecurityMetaData, VulnerabilityCaseType}
import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.http.javadsl.Http
import org.apache.pekko.http.javadsl.model.{ContentTypes, HttpHeader, HttpRequest}
import org.apache.pekko.http.scaladsl.PekkoCoreUtils
import org.apache.pekko.stream.Materializer
import org.apache.pekko.util.ByteString
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import org.junit.{Assert, FixMethodOrder, Test}

import java.net.ServerSocket
import java.util.UUID
import scala.concurrent.Await
import scala.concurrent.duration.{Duration, DurationInt}
import scala.jdk.CollectionConverters._
import scala.jdk.javaapi.FutureConverters

@RunWith(classOf[SecurityInstrumentationTestRunner])
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = Array("org.apache.pekko", "scala"))
class PekkoHttpCoreTest {

  implicit val system: ActorSystem = ActorSystem()
  implicit val materializer: Materializer = Materializer.createMaterializer(system)

  val PekkoServer = new PekkoServer()
  val playServer = new PlayServer()
  var port: Int = getRandomPort
  val baseUrl: String = "http://localhost:" + port
  val asyncUrl: String = "/asyncPing"
  val syncUrl: String = "/ping"
  val contentType: String = "text/plain"
  val responseBody: String = "Hoops!"
  val requestBody: String = "Hurray!"

  @Test
  def syncHandlerPekkoServerTestWithPekkoServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(headerValue)
    introspector.setK2TracingData(headerValue)
    introspector.setK2ParentId(headerValue)

    val headers: Seq[HttpHeader] = makeHttpRequest(async = false, withPlay = false)

    // assertions
    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    assertCSECHeaders(headers, headerValue)
    val operations = introspector.getOperations
    for ( op <- operations.asScala){
      op match {
        case operation: SSRFOperation => assertSSRFOperation(operation, syncUrl)
        case operation: RXSSOperation => assertRXSSOperation(operation)
        case _ =>
      }
    }
    assertMetaData(introspector.getSecurityMetaData)
  }

  @Test
  def asyncHandlerPekkoServerTestWithPekkoServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(headerValue)
    introspector.setK2TracingData(headerValue)
    introspector.setK2ParentId(headerValue)

    val headers: Seq[HttpHeader] = makeHttpRequest(async = true, withPlay = false)

    // assertions
    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    assertCSECHeaders(headers, headerValue)
    val operations = introspector.getOperations
    for (op <- operations.asScala){
      op match {
        case operation: SSRFOperation => assertSSRFOperation(operation, asyncUrl)
        case operation: RXSSOperation => assertRXSSOperation(operation)
        case _ =>
      }
    }
    assertMetaData(introspector.getSecurityMetaData)
  }

  @Test
  def syncHandlerPekkoServerTestWithPlayServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(headerValue)
    introspector.setK2TracingData(headerValue)
    introspector.setK2ParentId(headerValue)

    val headers: Seq[HttpHeader] = makeHttpRequest(async = false, withPlay = true)

    // assertions
    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    assertCSECHeaders(headers, headerValue)
    val operations = introspector.getOperations
    for (op <- operations.asScala){
      op match {
        case operation: SSRFOperation => assertSSRFOperation(operation, syncUrl)
        case operation: RXSSOperation => assertRXSSOperation(operation)
        case _ =>
      }
    }
    assertMetaData(introspector.getSecurityMetaData)
  }

  @Test
  def asyncHandlerPekkoServerTestWithPlayServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(headerValue)
    introspector.setK2TracingData(headerValue)
    introspector.setK2ParentId(headerValue)

    val headers: Seq[HttpHeader] = makeHttpRequest(async = true, withPlay = true)

    // assertions
    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    assertCSECHeaders(headers, headerValue)
    val operations = introspector.getOperations
    for (op <- operations.asScala){
      op match {
        case operation: SSRFOperation => assertSSRFOperation(operation, asyncUrl)
        case operation: RXSSOperation => assertRXSSOperation(operation)
        case _ =>
      }
    }
    assertMetaData(introspector.getSecurityMetaData)
  }

  @Trace(dispatcher = true, nameTransaction = true)
  private def makeHttpRequest(async: Boolean, withPlay: Boolean): Seq[HttpHeader] = {
    if (withPlay) {
      // start play-pekko server & make request
      playServer.start(port, async)

      Await.result(FutureConverters.asScala(Http(system = system).singleRequest(
        HttpRequest
          .GET(baseUrl + (if (async) asyncUrl else syncUrl))
          .withEntity(ContentTypes.TEXT_PLAIN_UTF8, ByteString.fromString(requestBody)))), new DurationInt(20).seconds)

      playServer.stop()
      playServer.getHeaders
    } else {
      // start pekko server & make request
      PekkoServer.start(port, async)

      Await.result(FutureConverters.asScala(Http(system = system).singleRequest(
        HttpRequest
          .GET(baseUrl + (if (async) asyncUrl else syncUrl))
          .withEntity(ContentTypes.TEXT_PLAIN_UTF8, ByteString.fromString(requestBody)))), new DurationInt(20).seconds)

      PekkoServer.stop()
      PekkoServer.getHeaders
    }
  }

  def getRandomPort: Int = {
    var port: Int = 0
    try {
      val socket: ServerSocket = new ServerSocket(0)
      port = socket.getLocalPort
      socket.close()
    } catch {
      case _: Exception => throw new RuntimeException("Unable to allocate ephemeral port")
    }
    port
  }

  private def assertSSRFOperation(operation: SSRFOperation, url: String): Unit = {
    Assert.assertFalse("operation should not be empty", operation.isEmpty)
    Assert.assertFalse("JNDILookup should be false", operation.isJNDILookup)
    Assert.assertFalse("LowSeverityHook should be disabled", operation.isLowSeverityHook)
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType)
    Assert.assertEquals("Invalid executed method name.", PekkoCoreUtils.METHOD_SINGLE_REQUEST, operation.getMethodName)
    Assert.assertEquals("Invalid executed parameters.", baseUrl + url, operation.getArg)
  }
  private def assertCSECHeaders(headers: Seq[HttpHeader], headerVal: String): Unit = {
    Assert.assertTrue(
      String.format("%s CSEC header should be present", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
      headers.exists(header => header.name().contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID))
    )
    Assert.assertTrue(
      String.format("Invalid CSEC header value for: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
      headers.exists(header => header.value().contains(headerVal))
    )

    Assert.assertTrue(
      String.format("%s CSEC header should be present", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
      headers.exists(header => header.name().contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER))
    )
    Assert.assertTrue(
      String.format("Invalid CSEC header value for: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
      headers.exists(header => header.value().contains(String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;", headerVal)))
    )

    Assert.assertTrue(
      String.format("%s CSEC header should be present", GenericHelper.CSEC_PARENT_ID),
      headers.exists(header => header.name().contains(GenericHelper.CSEC_PARENT_ID))
    )
    Assert.assertTrue(
      String.format("Invalid CSEC header value for: %s", GenericHelper.CSEC_PARENT_ID),
      headers.exists(header => header.value().contains(headerVal))
    )
  }
  private def assertRXSSOperation(operation: RXSSOperation): Unit = {
    Assert.assertFalse("operation should not be empty", operation.isEmpty)
    Assert.assertFalse("LowSeverityHook should be disabled", operation.isLowSeverityHook)
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType)
    Assert.assertEquals("Invalid executed method name.", "apply", operation.getMethodName)

    Assert.assertFalse("request should not be empty", operation.getRequest.isEmpty)
    Assert.assertEquals("Invalid request content-type.", contentType, operation.getRequest.getContentType)
    Assert.assertEquals("Invalid requestBody.", requestBody, operation.getRequest.getBody.toString)
    Assert.assertEquals("Invalid protocol.", "http", operation.getRequest.getProtocol)

    Assert.assertFalse("response should not be empty", operation.getResponse.isEmpty)
    Assert.assertEquals("Invalid response content-type.", contentType, operation.getResponse.getResponseContentType)
    Assert.assertEquals("Invalid responseBody.", responseBody, operation.getResponse.getResponseBody.toString)
  }
  private def assertMetaData(metaData: SecurityMetaData): Unit = {
    Assert.assertFalse("response should not be empty", metaData.getRequest.isEmpty)
    Assert.assertEquals("Invalid response content-type.", contentType, metaData.getRequest.getContentType)
    Assert.assertEquals("Invalid responseBody.", requestBody, metaData.getRequest.getBody.toString)
    Assert.assertFalse("response should not be empty", metaData.getResponse.isEmpty)
    Assert.assertEquals("Invalid response content-type.", contentType, metaData.getResponse.getResponseContentType)
    Assert.assertEquals("Invalid responseBody.", responseBody, metaData.getResponse.getResponseBody.toString)
    Assert.assertEquals("Invalid protocol.", metaData.getRequest.getProtocol, "http")
  }
}
