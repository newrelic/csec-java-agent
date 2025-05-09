package com.nr.agent.security.instrumentation.blaze.server

import cats.effect.IO
import com.newrelic.agent.security.introspec.{InstrumentationTestConfig, SecurityInstrumentationTestRunner, SecurityIntrospector}
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ServletHelper}
import com.newrelic.api.agent.security.schema.operation.RXSSOperation
import com.newrelic.api.agent.security.schema.{SecurityMetaData, VulnerabilityCaseType}
import org.http4s.dsl.io._
import org.http4s.implicits._
import org.http4s.util.CaseInsensitiveString
import org.http4s.{Header, HttpRoutes}
import org.junit.runner.RunWith
import org.junit.{After, Assert, Before, Test}

import java.net.{HttpURLConnection, URL}
import java.util
import java.util.UUID

@RunWith(classOf[SecurityInstrumentationTestRunner])
@InstrumentationTestConfig(includePrefixes = Array("org.http4s", "com.newrelic.agent.security.http4s.blaze.server"))
class EmberServerBuilderTest {

  val hostname = "0.0.0.0"
  val port: Int = SecurityInstrumentationTestRunner.getIntrospector.getRandomPort
  val contentType: String = "text/plain"

  val emberServer = new Http4sTestServer(hostname, port,
    HttpRoutes.of[IO] {
      case _ -> Root / "hello" / name =>
        Ok(s"Hello, $name.").map(_.putHeaders(Header.Raw(CaseInsensitiveString.apply("content-type"), contentType)))
    }.orNotFound)

  @Before
  def setup(): Unit = {
    emberServer.start()
  }

  @After
  def reset(): Unit = {
    emberServer.stop()
  }


  @Test
  def emberServerTest(): Unit = {
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    Http4sTestUtils.makeRequest(s"http://$hostname:$port/hello/bob", addCSECHeader = false, "")

    val operations = introspector.getOperations
    Assert.assertTrue(operations.size() > 0)
    Assert.assertTrue(operations.get(0).isInstanceOf[RXSSOperation])

    assertRXSSOperation(operations.get(0).asInstanceOf[RXSSOperation])
    assertMetaData(introspector.getSecurityMetaData)
  }

  @Test
  def emberServerHeaderTest(): Unit = {
    val headerValue: String = String.valueOf(UUID.randomUUID())

    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    Http4sTestUtils.makeRequest(s"http://$hostname:$port/hello/bob", addCSECHeader = true, headerValue)

    val operations = introspector.getOperations
    Assert.assertTrue(operations.size() > 0)
    Assert.assertTrue(operations.get(0).isInstanceOf[RXSSOperation])

    assertRXSSOperation(operations.get(0).asInstanceOf[RXSSOperation])
    assertMetaData(introspector.getSecurityMetaData)
    assertCSECHeaders(headerValue, introspector.getSecurityMetaData.getRequest.getHeaders)
  }

  private def assertCSECHeaders(headerValue: String, headers: util.Map[String, String]): Unit = {
    Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID))
    Assert.assertEquals(String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue + "a", headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID))
    Assert.assertTrue(String.format("Missing CSEC header: %s", GenericHelper.CSEC_PARENT_ID), headers.containsKey(GenericHelper.CSEC_PARENT_ID))
    Assert.assertEquals(String.format("Invalid CSEC header value for:  %s", GenericHelper.CSEC_PARENT_ID), headerValue + "b", headers.get(GenericHelper.CSEC_PARENT_ID))
    Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase))
    Assert.assertEquals(String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;", headerValue), headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase))
  }

  private def assertRXSSOperation(operation: RXSSOperation): Unit = {
    Assert.assertFalse("LowSeverityHook should be disabled", operation.isLowSeverityHook)
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType)
    Assert.assertEquals("Invalid executed method name.", "withHttpApp", operation.getMethodName)

    Assert.assertFalse("request should not be empty", operation.getRequest.isEmpty)
    Assert.assertEquals("Invalid Request content-type.", contentType, operation.getRequest.getContentType)
    Assert.assertEquals("Invalid protocol.", "http", operation.getRequest.getProtocol)
    Assert.assertFalse("Headers should not be empty", operation.getRequest.getHeaders.isEmpty)
    Assert.assertEquals("Invalid Request body", "body extract", operation.getRequest.getBody.toString)

    Assert.assertFalse("response should not be empty", operation.getResponse.isEmpty)
    Assert.assertEquals("Invalid response content-type.", contentType, operation.getResponse.getResponseContentType)
    Assert.assertFalse("Headers should not be empty", operation.getResponse.getHeaders.isEmpty)
    Assert.assertEquals("Invalid Response body", "Hello, bob.", operation.getResponse.getBody.toString)
    Assert.assertEquals("Invalid Response code", 200, operation.getResponse.getStatusCode)
  }

  private def assertMetaData(metaData: SecurityMetaData): Unit = {
    Assert.assertFalse("request should not be empty", metaData.getRequest.isEmpty)
    Assert.assertEquals("Invalid Request content-type.", contentType, metaData.getRequest.getContentType)
    Assert.assertEquals("Invalid protocol.", "http", metaData.getRequest.getProtocol)
    Assert.assertEquals("Invalid Request body", "body extract", metaData.getRequest.getBody.toString)
    Assert.assertFalse("Headers should not be empty", metaData.getRequest.getHeaders.isEmpty)

    Assert.assertFalse("response should not be empty", metaData.getResponse.isEmpty)
    Assert.assertEquals("Invalid response content-type.", contentType, metaData.getResponse.getResponseContentType)
    Assert.assertEquals("Invalid Response code", 200, metaData.getResponse.getStatusCode)
    Assert.assertFalse("Headers should not be empty", metaData.getResponse.getHeaders.isEmpty)
    Assert.assertEquals("Invalid Response body", "Hello, bob.", metaData.getResponse.getBody.toString)
  }
}

object Http4sTestUtils {
  def makeRequest(url: String, addCSECHeader: Boolean, headerValue: String): Unit = {
    val u: URL = new URL(url)
    val conn = u.openConnection.asInstanceOf[HttpURLConnection]
    conn.setDoOutput(true)

    conn.setRequestProperty("content-type", "text/plain")

    if (addCSECHeader) {
      conn.setRequestProperty(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, headerValue + "a")
      conn.setRequestProperty(GenericHelper.CSEC_PARENT_ID, headerValue + "b")
      conn.setRequestProperty(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;", headerValue))
    }

    val stream = conn.getOutputStream
    stream.write("body extract".getBytes)

    conn.connect()
    println(conn.getResponseCode)
  }
}
