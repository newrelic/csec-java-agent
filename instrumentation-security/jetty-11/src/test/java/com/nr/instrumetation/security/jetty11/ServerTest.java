package com.nr.instrumetation.security.jetty11;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import security.org.eclipse.jetty11.server.server.HttpServletHelper;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.After;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"security.org.eclipse.jetty11"})
public class ServerTest {
    public final static int PORT = getRandomPort();
    public final static String ENDPOINT = String.format("http://localhost:%d/", PORT);

    private Server server;

    @After
    public void teardown() throws Exception {
        if (server.isRunning()) {
            server.stop();
        }
    }

    @Test
    public void testHandle() throws Exception {
        start();
        String headerValue = service();

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
        Assert.assertEquals("Wrong URL detected", "/TestUrl", operation.getRequest().getUrl());
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
        start1();
        String headerValue = service();

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
        Assert.assertEquals("Wrong URL detected", "/TestUrl", operation.getRequest().getUrl());
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
        start();
        service1();

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
        Assert.assertEquals("Wrong URL detected", "/TestUrl", operation.getRequest().getUrl());
        Assert.assertEquals("Wrong port detected", PORT, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());
    }

    @Test
    public void testHandle3() throws Exception {
        start1();
        service1();

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
        Assert.assertEquals("Wrong URL detected", "/TestUrl", operation.getRequest().getUrl());
        Assert.assertEquals("Wrong port detected", PORT, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());
    }

    private void start() throws Exception {
        server = new Server(PORT);
        ServletHolder holder = new ServletHolder(
                new HttpServlet() {
                    @Override
                    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
                        resp.setContentType("text/plain;charset=utf-8");
                        resp.setStatus(HttpServletResponse.SC_OK);
                    }
                }
        );
        ServletContextHandler handler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        handler.setContextPath("/");
        server.setHandler(handler);
        handler.addServlet(holder, "/*");
        server.start();
    }

    private void start1() throws Exception {
        server = new Server(PORT);
        server.setHandler(
                new AbstractHandler() {
                    @Override
                    public void handle(String target, Request baseReq, HttpServletRequest req, HttpServletResponse res){
                        res.setContentType("text/plain;charset=utf-8");
                        res.setStatus(HttpServletResponse.SC_OK);
                        baseReq.setHandled(true);
                    }
                }
        );
        server.start();
    }

    @Trace(dispatcher = true)
    private String service() throws Exception {
        String headerValue = String.valueOf(UUID.randomUUID());
        URL u = new URL(ENDPOINT);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();

        conn.setRequestProperty("content-type", "text/plain;charset=utf-8");
        conn.setRequestMethod("GET");
        conn.setRequestProperty(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, headerValue);
        conn.setRequestProperty(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, headerValue);
        conn.connect();

        conn.getResponseCode();
        return headerValue;
    }
    @Trace(dispatcher = true)
    private void service1() throws Exception {
        URL u = new URL(ENDPOINT);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();

        conn.setRequestProperty("content-type", "text/plain;charset=utf-8");
        conn.setRequestMethod("GET");
        conn.connect();

        conn.getResponseCode();
    }

    private static int getRandomPort() {
        try (ServerSocket socket = new ServerSocket(0)){
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port ");
        }
    }
}
