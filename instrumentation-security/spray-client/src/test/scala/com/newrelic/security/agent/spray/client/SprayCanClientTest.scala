/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.security.agent.spray.client

import akka.actor._
import com.newrelic.agent.security.instrumentation.spray.client.SprayUtils
import com.newrelic.agent.security.introspec.internal.HttpServerLocator
import com.newrelic.agent.security.introspec.{HttpTestServer, InstrumentationTestConfig, SecurityInstrumentationTestRunner, SecurityIntrospector}
import com.newrelic.api.agent.security.instrumentation.helpers.{GenericHelper, ServletHelper}
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType
import com.newrelic.api.agent.security.schema.operation.SSRFOperation
import com.newrelic.security.test.marker.{Java11IncompatibleTest, Java17IncompatibleTest}
import org.junit.experimental.categories.Category
import org.junit.runner.RunWith
import org.junit._
import org.junit.runners.MethodSorters
import spray.client.pipelining
import spray.client.pipelining.Get

import java.util.UUID
import scala.util.{Failure, Success}

//// Not compatible with Java 11+ and Scala 2.13+ https://github.com/scala/bug/issues/12340
@Category( Array(classOf[Java11IncompatibleTest], classOf[Java17IncompatibleTest] ))
@RunWith(classOf[SecurityInstrumentationTestRunner])
@InstrumentationTestConfig(includePrefixes = Array("spray", "scala", "com.newrelic.agent.security.instrumentation"))
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SprayCanClientTest {
  var server :HttpTestServer = HttpServerLocator.createAndStart()
  implicit var system: ActorSystem = ActorSystem("spray-client")
  val endpoint :String = server.getEndPoint.toString;

  @After
  def after(): Unit = {
    server.shutdown()
  }

  @Test
  def testSendReceive(): Unit = {
    server.getHeaders.clear()
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector

    requestApi()

    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    val operations: SSRFOperation = introspector.getOperations.get(0).asInstanceOf[SSRFOperation]
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operations.getCaseType)
    Assert.assertEquals("Invalid method-name.", SprayUtils.METHOD_SEND_RECEIVE, operations.getMethodName)
    Assert.assertEquals("Invalid ssrf arg.", endpoint, operations.getArg)

    val header: java.util.Map[String, String] = server.getHeaders
    Assert.assertFalse(String.format("Found CSEC header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), header.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID))
    Assert.assertFalse(String.format("Found CSEC header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), header.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER))
    Assert.assertFalse(String.format("Found CSEC header: %s", GenericHelper.CSEC_PARENT_ID), header.containsKey(GenericHelper.CSEC_PARENT_ID))
  }

  @Test
  def testSendReceiveWithHeader(): Unit = {
    val headerValue = String.valueOf(UUID.randomUUID)
    val introspector: SecurityIntrospector = SecurityInstrumentationTestRunner.getIntrospector
    introspector.setK2FuzzRequestId(headerValue)
    introspector.setK2TracingData(headerValue)
    introspector.setK2ParentId(headerValue)

    requestApi()


    Assert.assertTrue("No operations detected", introspector.getOperations.size() > 0)
    val operations: SSRFOperation = introspector.getOperations.get(0).asInstanceOf[SSRFOperation]
    Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operations.getCaseType)
    Assert.assertEquals("Invalid method-name.", SprayUtils.METHOD_SEND_RECEIVE, operations.getMethodName)
    Assert.assertEquals("Invalid ssrf arg.", endpoint, operations.getArg)

    val header: java.util.Map[String, String] = server.getHeaders
    Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), header.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID))
    Assert.assertEquals(
      String.format("Invalid CSEC header value for: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
      headerValue,
      header.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
    )

    Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), header.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase))
    Assert.assertEquals(
      String.format("Invalid CSEC header value for: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
      String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;", headerValue),
      header.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase)
    )
    Assert.assertTrue(String.format("Missing CSEC header: %s", GenericHelper.CSEC_PARENT_ID), header.containsKey(GenericHelper.CSEC_PARENT_ID))
    Assert.assertEquals(
      String.format("Invalid CSEC header value for: %s", GenericHelper.CSEC_PARENT_ID),
      headerValue,
      header.get(GenericHelper.CSEC_PARENT_ID)
    )
  }


  def requestApi()(implicit system: ActorSystem): Unit = {
    import system.dispatcher
    val pipeline = pipelining.sendReceive
    val responseFuture = pipeline {Get(endpoint)}

    responseFuture onComplete {
      case Success(result) =>
        println("The API call was successful...: " + result)
        system.shutdown()

      case Failure(error) =>
        println(error, "Couldn't get elevation")
        system.shutdown()
    }
    system.awaitTermination
  }
}
