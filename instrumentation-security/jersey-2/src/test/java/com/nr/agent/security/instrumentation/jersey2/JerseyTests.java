/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.jersey2;

import com.newrelic.agent.security.instrumentation.jersey2.HttpRequestHelper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.security.test.marker.Java11IncompatibleTest;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import com.newrelic.security.test.marker.Java21IncompatibleTest;
import com.newrelic.security.test.marker.Java23IncompatibleTest;
import com.newrelic.security.test.marker.Java9IncompatibleTest;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.util.Header;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.server.ContainerResponse;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.newrelic.agent.security.instrumentation.jersey2"})
@Category({ Java9IncompatibleTest.class, Java11IncompatibleTest.class, Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class JerseyTests {

    private static HttpServer server;
    private static int port;
    private static final String PACKAGE = "com.nr.agent.security.instrumentation.jersey2.resources";
    private static URL url;
    private final String headerValue = String.valueOf(UUID.randomUUID());

    @BeforeClass
    public static void setUp() throws MalformedURLException, URISyntaxException {
        getRandomPort();
        url = new URL("http://localhost:" + port + "/api");
        server = GrizzlyHttpServerFactory.createHttpServer(url.toURI(), new ResourceConfig().packages(PACKAGE));
        try {
            server.start();
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }

    @AfterClass
    public static void tearDown() {
        if (server.isStarted()) server.stop();
    }

    @Test
    public void handleTest() {
        String[] responseBody = fireRequest("/operation/sync");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        assertTrue(introspector.getSecurityMetaData().getMetaData().isUserLevelServiceMethodEncountered());
        assertOperation(introspector.getOperations(),false, introspector.getRequestInStreamHash(),responseBody);
    }

    @Test
    public void asyncHandleTest() {
        String[] responseBody = fireRequest("/operation/async");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        assertTrue(introspector.getSecurityMetaData().getMetaData().isUserLevelServiceMethodEncountered());
        assertOperation(introspector.getOperations(),false, introspector.getRequestInStreamHash(), responseBody);
    }
    @Test
    public void handleHeaderTest() {
        String[] responseBody = fireRequest1("/operation/sync");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        assertTrue(introspector.getSecurityMetaData().getMetaData().isUserLevelServiceMethodEncountered());
        assertOperation(introspector.getOperations(), true, introspector.getRequestInStreamHash(), responseBody);

    }

    @Test
    public void asyncHandleHeaderTest() {
        String[] responseBody = fireRequest1("/operation/async");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        assertTrue(introspector.getSecurityMetaData().getMetaData().isUserLevelServiceMethodEncountered());
        assertOperation(introspector.getOperations(), false, introspector.getRequestInStreamHash(), responseBody);
    }

    private String[] fireRequest(final String path) {
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(url.toString()).path(path).queryParam("sleep", 1);
        Response response = target.request().header(Header.ContentType.toString(), MediaType.APPLICATION_JSON).get();
        try (BufferedReader br = new BufferedReader(new InputStreamReader((InputStream)response.getEntity()))
        ){
            String result = br.readLine();
            return new String[] { result, String.valueOf(response.getEntity().hashCode()) };
        } catch (IOException e) {
            response.close();
            client.close();
            throw new RuntimeException("error connecting to server");
        }
    }
    private String[] fireRequest1(final String path) {
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(url.toString()).path(path);
        Response response = target.request().header(Header.ContentType.toString(), MediaType.APPLICATION_JSON)
                .header(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, headerValue)
                .header(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, headerValue)
                .header(GenericHelper.CSEC_PARENT_ID, headerValue)
                .get();
        try (BufferedReader br = new BufferedReader(new InputStreamReader((InputStream)response.getEntity()))){
            String result = br.readLine();
            return new String[] { result, String.valueOf(response.getEntity().hashCode()) };
        } catch (IOException e) {
            throw new RuntimeException("error connecting to server");
        } finally {
            response.close();
            client.close();
        }
    }

    private void assertOperation(List<AbstractOperation> operations, boolean hasHeaders, Set<?> hashCode, String... responseBody) {
        assertFalse(operations.isEmpty());
        assertTrue(operations.get(0) instanceof RXSSOperation);
        RXSSOperation operation = (RXSSOperation) operations.get(0);

        assertEquals(HttpRequestHelper.CONTAINER_RESPONSE_METHOD_NAME, operation.getMethodName());
        assertEquals(ContainerResponse.class.getName(), operation.getClassName());
        assertEquals(VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());

        // assert the security request;
        HttpRequest request = operation.getRequest();
        assertFalse(request.isEmpty());
        assertEquals(MediaType.APPLICATION_JSON, request.getContentType());
        assertEquals(port, request.getServerPort());
        assertEquals("127.0.0.1", request.getClientIP());
        assertTrue(request.isRequestParsed());
        assertEquals("http", request.getProtocol());

        if(hasHeaders){
            Map<String, String> headers = request.getHeaders();

            assertTrue(
                    String.format("Missing CSEC header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
                    , headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
            );
            assertEquals(
                    String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                    headerValue, headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
            );
            assertTrue(
                    String.format("Missing CSEC header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                    headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
            );
            assertEquals(
                    String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                    headerValue, headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
            );
            assertTrue(
                    String.format("Missing CSEC header: %s", GenericHelper.CSEC_PARENT_ID),
                    headers.containsKey(GenericHelper.CSEC_PARENT_ID.toLowerCase())
            );
            assertEquals(
                    String.format("Invalid CSEC header value for:  %s", GenericHelper.CSEC_PARENT_ID),
                    headerValue, headers.get(GenericHelper.CSEC_PARENT_ID.toLowerCase())
            );
        }

        // assert the security response
        HttpResponse response = operation.getResponse();
        assertFalse(response.isEmpty());
        assertEquals(MediaType.TEXT_HTML, response.getResponseContentType());
        assertEquals(2, responseBody.length);
        assertEquals(responseBody[0], response.getResponseBody().toString());
        assertFalse(hashCode.isEmpty());
        assertEquals(Collections.singleton(Integer.parseInt(responseBody[1])), hashCode);
    }
    private static void getRandomPort()
    {
        try (ServerSocket socket = new ServerSocket(0)){
            port = socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port");
        }
    }
}
