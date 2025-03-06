package com.nr.agent.security.instrumentation.akka.http.core_10

import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.model.{ContentTypes, HttpEntity, HttpHeader, HttpRequest, HttpResponse}
import akka.stream.ActorMaterializer
import akka.util.ByteString
import com.newrelic.agent.security.introspec.{InstrumentationTestConfig, SecurityInstrumentationTestRunner, SecurityIntrospector}
import com.newrelic.api.agent.Trace
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ServletHelper}
import com.newrelic.api.agent.security.schema.operation.RXSSOperation
import com.newrelic.api.agent.security.schema.{SecurityMetaData, VulnerabilityCaseType}
import com.newrelic.security.test.marker.{Java11IncompatibleTest, Java17IncompatibleTest}
import org.junit.experimental.categories.Category
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import org.junit.{Assert, FixMethodOrder, Test}

import java.util.UUID
import scala.collection.JavaConverters
import scala.concurrent.Await
import scala.concurrent.duration.DurationInt

@RunWith(classOf[SecurityInstrumentationTestRunner])
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = Array("akka", "scala"))
@Category(Array(classOf[Java11IncompatibleTest], classOf[Java17IncompatibleTest]))
class AkkaHttpCoreTest {

  implicit val system: ActorSystem = ActorSystem()
  implicit val materializer: ActorMaterializer = ActorMaterializer()

  val akkaServer = new AkkaServer()
  var port: Int = SecurityInstrumentationTestRunner.getIntrospector.getRandomPort
  val baseUrl: String = "http://localhost:%s/".format(port)

  val contentType: String = "text/plain"
  val responseBody: String = "Hello, World!"
  val requestBody: String = "Hurray!"

  @Test
  def syncHandlerAkkaServerTestWithAkkaServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector

    val httpResponse = makeHttpRequest(headerValue)

    // assertions
    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    assertCSECHeaders( headers= httpResponse.headers, headerVal = headerValue)
    val operations = introspector.getOperations
    for (op <- JavaConverters.collectionAsScalaIterable(operations)){
      op match {
        case operation: RXSSOperation => assertRXSSOperation(operation)
        case _ =>
      }
    }
    assertMetaData(introspector.getSecurityMetaData)
  }

  @Trace(dispatcher = true, nameTransaction = true)
  private def makeHttpRequest(header: String): HttpResponse = {
    // start akka server & make request
    akkaServer.start(port)

    val response = Await.result(
      Http().singleRequest(
        HttpRequest(uri = baseUrl + header,
          entity = HttpEntity.Strict.apply(ContentTypes.`text/plain(UTF-8)`, ByteString.fromString(requestBody)))),
      new DurationInt(15).seconds)

    akkaServer.stop()
    response
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
      headers.exists(header => header.value().contains(headerVal))
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
    Assert.assertEquals("Invalid response content-type.", operation.getRequest.getContentType, contentType)
    Assert.assertEquals("Invalid responseBody.", operation.getRequest.getBody.toString, requestBody)
    Assert.assertEquals("Invalid protocol.", operation.getRequest.getProtocol, "http")

    Assert.assertFalse("response should not be empty", operation.getResponse.isEmpty)
    Assert.assertEquals("Invalid response content-type.", operation.getResponse.getResponseContentType, contentType)
    Assert.assertEquals("Invalid responseBody.", operation.getResponse.getResponseBody.toString, responseBody)
  }

  private def assertMetaData(metaData: SecurityMetaData): Unit = {
    Assert.assertFalse("response should not be empty", metaData.getResponse.isEmpty)
    Assert.assertEquals("Invalid response content-type.", metaData.getRequest.getContentType, contentType)
    Assert.assertEquals("In valid responseBody.", metaData.getRequest.getBody.toString, requestBody)
    Assert.assertFalse("response should not be empty", metaData.getRequest.isEmpty)
    Assert.assertEquals("Invalid response content-type.", metaData.getResponse.getResponseContentType, contentType)
    Assert.assertEquals("Invalid responseBody.", metaData.getResponse.getResponseBody.toString, responseBody)
    Assert.assertEquals("Invalid protocol.", metaData.getRequest.getProtocol, "http")
  }
}
