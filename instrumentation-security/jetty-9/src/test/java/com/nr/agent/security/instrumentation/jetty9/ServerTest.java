package com.nr.agent.security.instrumentation.jetty9;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.agent.security.instrumentation.jetty9.HttpServletHelper;
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

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.eclipse.jetty", "com.newrelic.agent.security.instrumentation.jetty9"})
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
                String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
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
        
        Assert.assertEquals("Wrong port detected", PORT, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());
    }
    @Test
    public void testCSECHeaders() throws Exception {
        start1();
        String fuzzHeader = "FILE_OPERATION--123:IAST:native:__K2PM0__:IAST:./tmp/file:IAST:SAFE:IAST:1:IAST:1:IAST:2aabd9833907ae4cde0120e4352c0da72d9e1acfcf298d6801b7120586d1df9d:IAST:02642fa0c3542fe5997eea314c0f5eec5b744ea83f168e998006111f9fa4fbd2";
        String headerValue = serviceWithHeaders(fuzzHeader);

        Thread.sleep(100);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected", operations.isEmpty());
        Assert.assertEquals("Extra operations detected", 1, operations.size());

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());

        Assert.assertEquals("Wrong port detected", PORT, targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "handle", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", targetOperation.getRequest().getContentType());

        Map<String, String> headers = targetOperation.getRequest().getHeaders();
        Assert.assertTrue(
                String.format("Missing header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
        );
        Assert.assertEquals(
                String.format("Invalid header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                fuzzHeader,
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
        Assert.assertTrue(
                String.format("Missing K2 header: %s", GenericHelper.CSEC_PARENT_ID),
                headers.containsKey(GenericHelper.CSEC_PARENT_ID)
        );
        Assert.assertEquals(
                String.format("Invalid K2 header value for:  %s", GenericHelper.CSEC_PARENT_ID),
                headerValue, headers.get(GenericHelper.CSEC_PARENT_ID)
        );

        File f = new File("./tmp123");
        K2RequestIdentifier identifier = introspector.getSecurityMetaData().getFuzzRequestIdentifier();
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
    @Trace(dispatcher = true)
    private String serviceWithHeaders(String fuzzHeader) throws IOException, URISyntaxException {
        String headerValue = String.valueOf(UUID.randomUUID());
        URL url = new URL(ENDPOINT);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");

        conn.setRequestProperty(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, fuzzHeader);
        conn.setRequestProperty(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, headerValue);
        conn.setRequestProperty(GenericHelper.CSEC_PARENT_ID, headerValue);
        conn.connect();
        conn.getResponseCode();
        return  headerValue;
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
