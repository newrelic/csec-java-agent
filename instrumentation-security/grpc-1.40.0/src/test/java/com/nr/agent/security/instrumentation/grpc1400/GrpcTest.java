/*
 *
 *  * Copyright 2021 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package com.nr.agent.security.instrumentation.grpc1400;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.nr.agent.security.instrumentation.grpc1400.app.TestClient;
import com.nr.agent.security.instrumentation.grpc1400.app.TestServer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "io.grpc", "com.newrelic.agent.security.instrumentation.grpc1400" })
public class GrpcTest {

    private static TestServer server;
    private static TestClient client;
    private final String fuzzHeader = "FILE_OPERATION--123:IAST:native:__K2PM0__:IAST:./tmp/file:IAST:SAFE:IAST:1:IAST:1:IAST:2aabd9833907ae4cde0120e4352c0da72d9e1acfcf298d6801b7120586d1df9d:IAST:02642fa0c3542fe5997eea314c0f5eec5b744ea83f168e998006111f9fa4fbd2";

    @BeforeClass
    public static void before() throws Exception {
        server = new TestServer();
        server.start();
        client = new TestClient("localhost", server.getPort());
    }

    @AfterClass
    public static void after() throws InterruptedException {
        if (client != null) {
            client.shutdown();
        }
        if (server != null) {
            server.stop();
        }
    }

    @Test
    public void testBlockingRequest() throws JsonProcessingException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        introspector.setK2FuzzRequestId(fuzzHeader);
        introspector.setK2TracingData(headerValue);
        introspector.setK2ParentId(headerValue);

        client.helloBlocking("Blocking");

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("More/less than expected operations detected", 3, operations.size());
        for (AbstractOperation op : operations) {
            if (op instanceof SSRFOperation) {
                SSRFOperation operation = (SSRFOperation) op;
                Assert.assertEquals("Invalid executed parameters.", "grpc://localhost:"+server.getPort()+"/helloworld.Greeter/SayHello", operation.getArg());
                Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
                Assert.assertEquals("Invalid executed method name.", "start", operation.getMethodName());
            }
            else if (op instanceof RXSSOperation) {
                RXSSOperation operation = (RXSSOperation) op;
                Assert.assertNotNull("No target operation detected", operation);
                Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
                Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
//                Assert.assertEquals("Wrong method detected", "helloworld.Greeter/SayHello", operation.getRequest().getMethod());
                Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());
                Assert.assertEquals("Wrong port detected", server.getPort(), operation.getRequest().getServerPort());
                Assert.assertEquals("Wrong method name detected", "startCall", operation.getMethodName());
                Assert.assertEquals("Wrong Content-type detected", "application/grpc", operation.getRequest().getContentType());
                Assert.assertTrue("It is an gRPC request", operation.getRequest().getIsGrpc());

                Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), operation.getRequest().getHeaders().containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headerValue+";DUMMY_UUID/dummy-api-id/dummy-exec-id", operation.getRequest().getHeaders().get(
                        ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), fuzzHeader, operation.getRequest().getHeaders().get(
                        ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.toLowerCase()));
                Assert.assertTrue(String.format("Missing K2 header: %s", GenericHelper.CSEC_PARENT_ID), operation.getRequest().getHeaders().containsKey(GenericHelper.CSEC_PARENT_ID.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", GenericHelper.CSEC_PARENT_ID), headerValue, operation.getRequest().getHeaders().get(
                        GenericHelper.CSEC_PARENT_ID.toLowerCase()));
            }
        }
        String request = new ObjectMapper().writeValueAsString(introspector.getGRPCRequest());
        String response = new ObjectMapper().writeValueAsString(introspector.getGRPCResponse());
        Assert.assertEquals("Invalid request body.", "[{\"name\":\"Blocking\"}]", request);
        Assert.assertEquals("Invalid response body.", "[{\"message\":\"Hello Blocking\"}]", response);
        assertCSECHeaders(introspector.getSecurityMetaData().getFuzzRequestIdentifier());
    }

    @Test
    public void testFutureRequest() throws Exception {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        introspector.setK2FuzzRequestId(fuzzHeader);
        introspector.setK2TracingData(headerValue);
        introspector.setK2ParentId(headerValue);

        client.helloFuture("Future");

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("More/less than expected operations detected", 2, operations.size());
        for (AbstractOperation op : operations) {
            if (op instanceof SSRFOperation) {
                SSRFOperation operation = (SSRFOperation) op;
                Assert.assertEquals("Invalid executed parameters.", "grpc://localhost:"+server.getPort()+"/helloworld.Greeter/SayHello", operation.getArg());
                Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
                Assert.assertEquals("Invalid executed method name.", "start", operation.getMethodName());
            }
            else if (op instanceof RXSSOperation) {
                RXSSOperation operation = (RXSSOperation) op;
                Assert.assertNotNull("No target operation detected", operation);
                Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
                Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
//                Assert.assertEquals("Wrong method detected", "helloworld.Greeter/SayHello", operation.getRequest().getMethod());
                Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());
                Assert.assertEquals("Wrong port detected", server.getPort(), operation.getRequest().getServerPort());
                Assert.assertEquals("Wrong method name detected", "startCall", operation.getMethodName());
                Assert.assertEquals("Wrong Content-type detected", "application/grpc", operation.getRequest().getContentType());
                Assert.assertTrue("It is an gRPC request", operation.getRequest().getIsGrpc());

                Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), operation.getRequest().getHeaders().containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headerValue+";DUMMY_UUID/dummy-api-id/dummy-exec-id", operation.getRequest().getHeaders().get(
                        ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
                Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), operation.getRequest().getHeaders().containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), fuzzHeader, operation.getRequest().getHeaders().get(
                        ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.toLowerCase()));
                Assert.assertTrue(String.format("Missing K2 header: %s", GenericHelper.CSEC_PARENT_ID), operation.getRequest().getHeaders().containsKey(GenericHelper.CSEC_PARENT_ID.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", GenericHelper.CSEC_PARENT_ID), headerValue, operation.getRequest().getHeaders().get(
                        GenericHelper.CSEC_PARENT_ID.toLowerCase()));
            }
        }
        String request = new ObjectMapper().writeValueAsString(introspector.getGRPCRequest());
        String response = new ObjectMapper().writeValueAsString(introspector.getGRPCResponse());
        Assert.assertEquals("Invalid request body.", "[{\"name\":\"Future\"}]", request);
        Assert.assertEquals("Invalid response body.", "[{\"message\":\"Hello Future\"}]", response);
        assertCSECHeaders(introspector.getSecurityMetaData().getFuzzRequestIdentifier());
    }

    @Test
    public void testAsyncRequest() throws JsonProcessingException, InterruptedException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        introspector.setK2FuzzRequestId(fuzzHeader);
        introspector.setK2TracingData(headerValue);
        introspector.setK2ParentId(headerValue);

        client.helloAsync("Async");
        // wait for async call to finish
        Thread.sleep(500);

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("More/less than expected operations detected", 2, operations.size());
        for (AbstractOperation op : operations) {
            if (op instanceof SSRFOperation) {
                SSRFOperation operation = (SSRFOperation) op;
                Assert.assertEquals("Invalid executed parameters.", "grpc://localhost:"+server.getPort()+"/helloworld.Greeter/SayHello", operation.getArg());
                Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
                Assert.assertEquals("Invalid executed method name.", "start", operation.getMethodName());
            }
            else if (op instanceof RXSSOperation) {
                RXSSOperation operation = (RXSSOperation) op;
                Assert.assertNotNull("No target operation detected", operation);
                Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
                Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
//                Assert.assertEquals("Wrong method detected", "helloworld.Greeter/SayHello", operation.getRequest().getMethod());
                Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());
                Assert.assertEquals("Wrong port detected", server.getPort(), operation.getRequest().getServerPort());
                Assert.assertEquals("Wrong method name detected", "startCall", operation.getMethodName());
                Assert.assertEquals("Wrong Content-type detected", "application/grpc", operation.getRequest().getContentType());
                Assert.assertTrue("It is an gRPC request", operation.getRequest().getIsGrpc());

                Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), operation.getRequest().getHeaders().containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headerValue+";DUMMY_UUID/dummy-api-id/dummy-exec-id", operation.getRequest().getHeaders().get(
                        ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
                Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), operation.getRequest().getHeaders().containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), fuzzHeader, operation.getRequest().getHeaders().get(
                        ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.toLowerCase()));
                Assert.assertTrue(String.format("Missing K2 header: %s", GenericHelper.CSEC_PARENT_ID), operation.getRequest().getHeaders().containsKey(GenericHelper.CSEC_PARENT_ID.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", GenericHelper.CSEC_PARENT_ID), headerValue, operation.getRequest().getHeaders().get(
                        GenericHelper.CSEC_PARENT_ID.toLowerCase()));
            }
        }
        String request = new ObjectMapper().writeValueAsString(introspector.getGRPCRequest());
        String response = new ObjectMapper().writeValueAsString(introspector.getGRPCResponse());
        Assert.assertEquals("Invalid request body.", "[{\"name\":\"Async\"}]", request);
        Assert.assertEquals("Invalid response body.", "[{\"message\":\"Hello Async\"}]", response);
        assertCSECHeaders(introspector.getSecurityMetaData().getFuzzRequestIdentifier());
    }

    @Test
    public void testStreamingRequest() throws JsonProcessingException, InterruptedException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        introspector.setK2FuzzRequestId(fuzzHeader);
        introspector.setK2TracingData(headerValue);
        introspector.setK2ParentId(headerValue);

        client.helloStreaming("Streaming");
        // wait for streaming to finish
        Thread.sleep(500);

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("More/less than expected operations detected", 2, operations.size());
        for (AbstractOperation op : operations) {
            if (op instanceof SSRFOperation) {
                SSRFOperation operation = (SSRFOperation) op;
                Assert.assertEquals("Invalid executed parameters.", "grpc://localhost:"+server.getPort()+"/manualflowcontrol.StreamingGreeter/SayHelloStreaming", operation.getArg());
                Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
                Assert.assertEquals("Invalid executed method name.", "start", operation.getMethodName());
            }
            else if (op instanceof RXSSOperation) {
                RXSSOperation operation = (RXSSOperation) op;
                Assert.assertNotNull("No target operation detected", operation);
                Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
                Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
//                Assert.assertEquals("Wrong method detected", "helloworld.Greeter/SayHello", operation.getRequest().getMethod());
                Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());
                Assert.assertEquals("Wrong port detected", server.getPort(), operation.getRequest().getServerPort());
                Assert.assertEquals("Wrong method name detected", "startCall", operation.getMethodName());
                Assert.assertEquals("Wrong Content-type detected", "application/grpc", operation.getRequest().getContentType());
                Assert.assertTrue("It is an gRPC request", operation.getRequest().getIsGrpc());

                Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), operation.getRequest().getHeaders().containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headerValue+";DUMMY_UUID/dummy-api-id/dummy-exec-id", operation.getRequest().getHeaders().get(
                        ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
                Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), operation.getRequest().getHeaders().containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), fuzzHeader, operation.getRequest().getHeaders().get(
                        ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.toLowerCase()));
                Assert.assertTrue(String.format("Missing K2 header: %s", GenericHelper.CSEC_PARENT_ID), operation.getRequest().getHeaders().containsKey(GenericHelper.CSEC_PARENT_ID.toLowerCase()));
                Assert.assertEquals(String.format("Invalid K2 header value for:  %s", GenericHelper.CSEC_PARENT_ID), headerValue, operation.getRequest().getHeaders().get(
                        GenericHelper.CSEC_PARENT_ID.toLowerCase()));
            }
        }
        String request = new ObjectMapper().writeValueAsString(introspector.getGRPCRequest());
        String response = new ObjectMapper().writeValueAsString(introspector.getGRPCResponse());
        Assert.assertEquals("Invalid request body.", "[{\"name\":\"Streaming1\"},{\"name\":\"Streaming2\"},{\"name\":\"Streaming3\"},{\"name\":\"Streaming4\"}]", request);
        Assert.assertEquals("Invalid response body.", "[{\"message\":\"Hello Streaming1\"},{\"message\":\"Hello Streaming2\"},{\"message\":\"Hello Streaming3\"},{\"message\":\"Hello Streaming4\"}]", response);
        assertCSECHeaders(introspector.getSecurityMetaData().getFuzzRequestIdentifier());
    }
    private void assertCSECHeaders(K2RequestIdentifier identifier){
        File f = new File("./tmp123");
        String[] data = StringUtils.splitByWholeSeparatorWorker(fuzzHeader, ":IAST:", -1, false);
        Assert.assertTrue(data.length > 4);
        Assert.assertNotNull(identifier);
        Assert.assertEquals(fuzzHeader, identifier.getRaw());
        Assert.assertEquals(data[0], identifier.getApiRecordId());
        Assert.assertEquals(data[1], identifier.getRefId());
        Assert.assertEquals(data[2], identifier.getRefValue());
        Assert.assertEquals(data[3], identifier.getNextStage().getStatus());
        Assert.assertEquals(1, identifier.getTempFiles().size());
        Assert.assertEquals(f.getPath(), identifier.getTempFiles().get(0));
        f.deleteOnExit();
    }
}
