package com.nr.instrumentation.security.jetty12.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.security.test.marker.Java11IncompatibleTest;
import com.newrelic.security.test.marker.Java8IncompatibleTest;
import com.newrelic.security.test.marker.Java9IncompatibleTest;
import com.nr.instrumentation.security.jetty12.server.HttpServletHelper;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.util.Callback;
import org.junit.After;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Category({ Java8IncompatibleTest.class, Java9IncompatibleTest.class, Java11IncompatibleTest.class })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.nr.instrumentation.security.jetty12.server"})
public class ServerTest {
    public static int PORT = 0;
    public static String ENDPOINT = "http://localhost:%d/";

    private Server server;

    @After
    public void teardown() throws Exception {
        if (server!=null&&server.isRunning()) {
            server.stop();
        }
    }

    @Test
    public void testHandle() throws Exception {
        startWithServlet();
        String headerValue = serviceWithHeaders();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("userLevelService method was not encountered.", meta.isUserLevelServiceMethodEncountered());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        System.out.println(new ObjectMapper().writeValueAsString(operations));
        RXSSOperation operation = (RXSSOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", HttpServletHelper.SERVICE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());
        
        Assert.assertEquals("Wrong method", "GET", operation.getRequest().getMethod());
        Assert.assertEquals("Wrong port detected", PORT, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());

        Map<String, String> headers = operation.getRequest().getHeaders();
        Assert.assertTrue(
                String.format("Missing header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
        );
        Assert.assertEquals(
                String.format("Invalid header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                headerValue,
                headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
        );
        Assert.assertTrue(
                String.format("Missing header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
        Assert.assertEquals(
                String.format("Invalid header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                headerValue,
                headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
    }

    @Test
    public void testHandle1() throws Exception {
        startWithHandler();
        String headerValue = serviceWithHeaders();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("userLevelService Method was not encountered.", meta.isUserLevelServiceMethodEncountered());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        RXSSOperation operation = (RXSSOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", HttpServletHelper.SERVICE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());

        Assert.assertEquals("Wrong method", "GET", operation.getRequest().getMethod());
        Assert.assertEquals("Wrong port detected", PORT, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());

        Map<String, String> headers = operation.getRequest().getHeaders();
        Assert.assertTrue(
                String.format("Missing header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
        );
        Assert.assertEquals(
                String.format("Invalid header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                headerValue,
                headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
        );
        Assert.assertTrue(
                String.format("Missing header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
        Assert.assertEquals(
                String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                headerValue,
                headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
    }

    @Test
    public void testHandle2() throws Exception {
        startWithServlet();
        serviceWithoutHeaders();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("userLevelService method was not encountered.", meta.isUserLevelServiceMethodEncountered());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        RXSSOperation operation = (RXSSOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", HttpServletHelper.SERVICE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());

        Assert.assertEquals("Wrong method", "GET", operation.getRequest().getMethod());
        Assert.assertEquals("Wrong port detected", PORT, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());
    }

    @Test
    public void testHandle3() throws Exception {
        startWithHandler();
        serviceWithoutHeaders();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("userLevelService method was not encountered.", meta.isUserLevelServiceMethodEncountered());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        RXSSOperation operation = (RXSSOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", HttpServletHelper.SERVICE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());

        Assert.assertEquals("Wrong method", "GET", operation.getRequest().getMethod());
        Assert.assertEquals("Wrong port detected", PORT, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());
    }

    @Test
    public void testHandle4() throws Exception {
        startWithHandlerNonBlocking();
        serviceWithoutHeaders();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("userLevelService method was not encountered.", meta.isUserLevelServiceMethodEncountered());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        RXSSOperation operation = (RXSSOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", HttpServletHelper.SERVICE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());

        Assert.assertEquals("Wrong method", "GET", operation.getRequest().getMethod());
        Assert.assertEquals("Wrong port detected", PORT, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());
    }

    @Test
    public void testHandle5() throws Exception {
        startWithHandlerNonBlocking();
        String headerValue = serviceWithHeaders();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("userLevelService method was not encountered.", meta.isUserLevelServiceMethodEncountered());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        RXSSOperation operation = (RXSSOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", HttpServletHelper.SERVICE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", operation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());

        Assert.assertEquals("Wrong method", "GET", operation.getRequest().getMethod());
        Assert.assertEquals("Wrong port detected", PORT, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());

        Map<String, String> headers = operation.getRequest().getHeaders();
        Assert.assertTrue(
                String.format("Missing header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
        );
        Assert.assertEquals(
                String.format("Invalid header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                headerValue,
                headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
        );
        Assert.assertTrue(
                String.format("Missing header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
        Assert.assertEquals(
                String.format("Invalid header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                headerValue,
                headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
    }

    private void startWithServlet() throws Exception {
        PORT = getRandomPort();
        Server server = new Server(PORT);
//        server.setHandler(new ContextHandler(new MyServlet(), "/testapp/something?ok=34"));
        server.setHandler(new MyServlet());
        server.start();
    }

    private void startWithHandler() throws Exception {
        PORT = getRandomPort();
        server = new Server(PORT);
        server.setHandler(
                new Handler.Abstract() {
            @Override
            public boolean handle (Request request, Response response, Callback callback) throws Exception {
                System.out.println("Request 1 completed!");
                callback.succeeded();
                return true;
            }
        });
        server.start();
    }

    private void startWithHandlerNonBlocking() throws Exception {
        PORT = getRandomPort();
        server = new Server(PORT);
        server.setHandler(
                new Handler.Abstract.NonBlocking() {
                    @Override
                    public boolean handle (Request request, Response response, Callback callback) throws Exception {
                        System.out.println("Request 2 completed!");
                        callback.succeeded();
                        return true;
                    }
                });
        server.start();
    }

    @Trace(dispatcher = true)
    private void serviceWithoutHeaders() throws Exception {
        URL u = new URL(String.format(ENDPOINT, PORT));
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();

        conn.setRequestProperty("content-type", "text/plain;charset=utf-8");
        conn.setRequestMethod("GET");
        conn.connect();

        System.out.println(conn.getResponseCode());
    }

    @Trace(dispatcher = true)
    private String serviceWithHeaders() throws Exception {
        String headerValue = String.valueOf(UUID.randomUUID());
        URL u = new URL(String.format(ENDPOINT, PORT)+"testapp/something?ok=12");
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();

        conn.setRequestProperty("content-type", "text/plain;charset=utf-8");
        conn.setRequestMethod("GET");
        conn.setRequestProperty(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, headerValue);
        conn.setRequestProperty(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, headerValue);
        conn.connect();

        conn.getResponseCode();
        return headerValue;
    }

    private static int getRandomPort() {
        try (ServerSocket socket = new ServerSocket(0)){
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port ");
        }
    }
}
