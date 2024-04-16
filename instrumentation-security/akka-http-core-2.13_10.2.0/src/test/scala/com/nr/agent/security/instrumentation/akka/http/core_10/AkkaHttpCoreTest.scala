/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.akka.http.core_10

import akka.actor.ActorSystem
import akka.http.scaladsl.{AkkaCoreUtils, Http}
import akka.http.scaladsl.model.{ContentTypes, HttpEntity, HttpHeader, HttpRequest}
import akka.util.ByteString
import com.newrelic.agent.security.introspec.{InstrumentationTestConfig, SecurityInstrumentationTestRunner, SecurityIntrospector}
import com.newrelic.api.agent.Trace
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ServletHelper}
import com.newrelic.api.agent.security.schema.{K2RequestIdentifier, SecurityMetaData, StringUtils, VulnerabilityCaseType}
import com.newrelic.api.agent.security.schema.operation.{RXSSOperation, SSRFOperation}
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import org.junit.{Assert, FixMethodOrder, Test}

import java.io.File
import java.net.ServerSocket
import java.util.UUID
import scala.concurrent.duration.DurationInt
import scala.concurrent.Await
import scala.jdk.CollectionConverters._

@RunWith(classOf[SecurityInstrumentationTestRunner])
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = Array("akka", "scala"))
class AkkaHttpCoreTest {

  implicit val system: ActorSystem = ActorSystem()

  val akkaServer = new AkkaServer()
  val playServer = new PlayServer()
  var port: Int = getRandomPort
  val baseUrl: String = "http://localhost:" + port
  val asyncUrl: String = "/asyncPing"
  val syncUrl: String = "/ping"
  val contentType: String = "text/plain"
  val responseBody: String = "Hoops!"
  val requestBody: String = "Hurray!"
  val fuzzHeader = "FILE_OPERATION--123:IAST:native:__K2PM0__:IAST:./tmp/file:IAST:SAFE:IAST:1:IAST:1:IAST:2aabd9833907ae4cde0120e4352c0da72d9e1acfcf298d6801b7120586d1df9d:IAST:02642fa0c3542fe5997eea314c0f5eec5b744ea83f168e998006111f9fa4fbd2"

  @Test
  def syncHandlerAkkaServerTestWithAkkaServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(fuzzHeader)
    introspector.setK2TracingData(headerValue)
    introspector.setK2ParentId(headerValue)

    val headers: Seq[HttpHeader] = makeHttpRequest(async = false, withPlay = false)

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
    assertIASTFuzzIdentifier(introspector.getSecurityMetaData.getFuzzRequestIdentifier)
  }

  @Test
  def asyncHandlerAkkaServerTestWithAkkaServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(fuzzHeader)
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
    assertIASTFuzzIdentifier(introspector.getSecurityMetaData.getFuzzRequestIdentifier)
  }

  @Test
  def syncHandlerAkkaServerTestWithPlayServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(fuzzHeader)
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
    assertIASTFuzzIdentifier(introspector.getSecurityMetaData.getFuzzRequestIdentifier)
  }

  @Test
  def asyncHandlerAkkaServerTestWithPlayServer(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(fuzzHeader)
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
    assertIASTFuzzIdentifier(introspector.getSecurityMetaData.getFuzzRequestIdentifier)
  }

  @Trace(dispatcher = true, nameTransaction = true)
  private def makeHttpRequest(async: Boolean, withPlay: Boolean): Seq[HttpHeader] = {
    if (withPlay) {
      // start play-akka server & make request
      playServer.start(port, async)

      println("result of request: "+ Await.result(
        Http().singleRequest(
          HttpRequest(uri = baseUrl + (if (async) asyncUrl else syncUrl),
            entity = HttpEntity.Strict.apply(ContentTypes.`text/plain(UTF-8)`, ByteString.fromString(requestBody)))),
        new DurationInt(15).seconds)
      )

      playServer.stop()
      playServer.getHeaders
    } else {
      // start akka server & make request
      akkaServer.start(port, async)

      println("result of request: "+ Await.result(
        Http().singleRequest(
          HttpRequest(uri = baseUrl + (if (async) asyncUrl else syncUrl),
            entity = HttpEntity.Strict.apply(ContentTypes.`text/plain(UTF-8)`, ByteString.fromString(requestBody)))),
        new DurationInt(15).seconds)
      )

      akkaServer.stop()
      akkaServer.getHeaders
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
  private def assertIASTFuzzIdentifier(identifier: K2RequestIdentifier): Unit = {
    val f = new File("./tmp123")
    val data = StringUtils.splitByWholeSeparatorWorker(fuzzHeader, ":IAST:", -1, false)
    Assert.assertTrue(data.length > 4)
    Assert.assertNotNull(identifier)
    Assert.assertEquals(fuzzHeader, identifier.getRaw)
    Assert.assertEquals(data(0), identifier.getApiRecordId)
    Assert.assertEquals(data(1), identifier.getRefId)
    Assert.assertEquals(data(2), identifier.getRefValue)
    Assert.assertEquals(data(3), identifier.getNextStage.getStatus)
    Assert.assertEquals(1, identifier.getTempFiles.size)
    Assert.assertEquals(f.getPath, identifier.getTempFiles.get(0))
    f.deleteOnExit()
  }
  private def assertSSRFOperation(operation: SSRFOperation, url: String): Unit = {
    Assert.assertFalse("operation should not be empty", operation.isEmpty)
    Assert.assertFalse("JNDILookup should be false", operation.isJNDILookup)
    Assert.assertFalse("LowSeverityHook should be disabled", operation.isLowSeverityHook)
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType)
    Assert.assertEquals("Invalid executed method name.", AkkaCoreUtils.METHOD_SINGLE_REQUEST_IMPL, operation.getMethodName)
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
    Assert.assertEquals("Invalid responseBody.", metaData.getRequest.getBody.toString, requestBody)
    Assert.assertFalse("response should not be empty", metaData.getRequest.isEmpty)
    Assert.assertEquals("Invalid response content-type.", metaData.getResponse.getResponseContentType, contentType)
    Assert.assertEquals("Invalid responseBody.", metaData.getResponse.getResponseBody.toString, responseBody)
    Assert.assertEquals("Invalid protocol.", metaData.getRequest.getProtocol, "http")
  }
}
