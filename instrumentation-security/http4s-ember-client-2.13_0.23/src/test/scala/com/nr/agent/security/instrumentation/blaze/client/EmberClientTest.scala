package com.nr.agent.security.instrumentation.blaze.client

import cats.effect.unsafe.implicits.global
import cats.effect.{Async, IO}
import com.newrelic.agent.security.introspec.internal.HttpServerRule
import com.newrelic.agent.security.introspec.{InstrumentationTestConfig, SecurityInstrumentationTestRunner, SecurityIntrospector}
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ServletHelper}
import com.newrelic.api.agent.security.schema.operation.SSRFOperation
import com.newrelic.api.agent.security.schema.{AbstractOperation, VulnerabilityCaseType}
import com.nr.agent.security.instrumentation.blaze.client.Http4sTestUtils.makeRequest
import org.http4s.ember.client.EmberClientBuilder
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import org.junit.{Assert, FixMethodOrder, Rule, Test}

import java.util
import java.util.UUID
import scala.concurrent.duration.DurationInt

@RunWith(classOf[SecurityInstrumentationTestRunner])
@InstrumentationTestConfig(includePrefixes = Array("org.http4s", "com.newrelic.agent.security.instrumentation.http4s"))
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class EmberClientTest {

  @Rule
  def server: HttpServerRule = httpServer

  val httpServer = new HttpServerRule()

  @Test
  def blazeClientTest(): Unit = {

    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    makeRequest[IO](s"${server.getEndPoint}").unsafeRunTimed(2.seconds)
    assertSSRFOperation(introspector.getOperations)
  }

  @Test
  def blazeClientTestWithHeaders(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)

    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    setCSECHeaders(headerValue = headerValue, introspector = introspector)
    makeRequest[IO](s"${server.getEndPoint}").unsafeRunTimed(2.seconds)
    assertSSRFOperation(introspector.getOperations)
    verifyHeaders(headerValue, httpServer.getHeaders)
  }


  private def assertSSRFOperation(operations: util.List[AbstractOperation]): Unit = {
    Assert.assertTrue("Incorrect number of operations detected!", operations.size == 1)
    Assert.assertTrue("SSRFOperation not found!", operations.get(0).isInstanceOf[SSRFOperation])
    val operation: SSRFOperation = operations.get(0).asInstanceOf[SSRFOperation]

    Assert.assertFalse("operation should not be empty", operation.isEmpty)
    Assert.assertFalse("JNDILookup should be false", operation.isJNDILookup)
    Assert.assertFalse("LowSeverityHook should be disabled", operation.isLowSeverityHook)
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType)
    Assert.assertEquals("Invalid executed method name.", "run", operation.getMethodName)
    Assert.assertEquals("Invalid executed parameters.",  server.getEndPoint.toString, operation.getArg)
  }

  private def verifyHeaders(headerValue: String, headers: util.Map[String, String]): Unit = {
    Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID))
    Assert.assertEquals(String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue + "a", headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID))
    Assert.assertTrue(String.format("Missing CSEC header: %s", GenericHelper.CSEC_PARENT_ID), headers.containsKey(GenericHelper.CSEC_PARENT_ID))
    Assert.assertEquals(String.format("Invalid CSEC header value for:  %s", GenericHelper.CSEC_PARENT_ID), headerValue + "b", headers.get(GenericHelper.CSEC_PARENT_ID))
    Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase))
    Assert.assertEquals(String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;", headerValue), headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase))
  }

  private def setCSECHeaders(headerValue: String, introspector: SecurityIntrospector): Unit = {
    introspector.setK2FuzzRequestId(headerValue + "a")
    introspector.setK2ParentId(headerValue + "b")
    introspector.setK2TracingData(headerValue)
  }
}

object Http4sTestUtils {
  def makeRequest[F[_]: Async](url: String): F[String] = {
    val client = EmberClientBuilder.default[F].build
    client.use { c =>
      c.expect[String](url)
    }
  }
}

