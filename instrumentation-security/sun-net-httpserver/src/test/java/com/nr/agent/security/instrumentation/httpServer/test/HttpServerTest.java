package com.nr.agent.security.instrumentation.httpServer.test;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.security.test.marker.Java11IncompatibleTest;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import com.newrelic.security.test.marker.Java21IncompatibleTest;
import com.newrelic.security.test.marker.Java23IncompatibleTest;
import com.newrelic.security.test.marker.Java9IncompatibleTest;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.sun.net.httpserver"})
@Category({ Java11IncompatibleTest.class, Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class HttpServerTest {
    @ClassRule
    public static Httpserver server = new Httpserver();

    @Test
    public void testHandle() throws URISyntaxException, IOException, InterruptedException {
        handle();
        Thread.sleep(100);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Extra operations detected", 1, operations.size());

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());

        Assert.assertEquals("Wrong port detected", server.getEndPoint().getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "handle", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", targetOperation.getRequest().getContentType());
    }
    @Test
    public void testHandle1() throws URISyntaxException, IOException, InterruptedException {
        String headerValue = handle1();
        Thread.sleep(100);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Extra operations detected", 1, operations.size());

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());

        Assert.assertEquals("Wrong port detected", server.getEndPoint().getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "handle", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", targetOperation.getRequest().getContentType());

        Map<String, String> headers = targetOperation.getRequest().getHeaders();
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
        Assert.assertTrue(
                String.format("Missing K2 header: %s", GenericHelper.CSEC_PARENT_ID),
                headers.containsKey(GenericHelper.CSEC_PARENT_ID)
        );
        Assert.assertEquals(
                String.format("Invalid K2 header value for:  %s", GenericHelper.CSEC_PARENT_ID),
                headerValue, headers.get(GenericHelper.CSEC_PARENT_ID)
        );
    }
    @Test
    public void testHandle2() throws URISyntaxException, IOException, InterruptedException {
        int expectedHash = handle2();
        Thread.sleep(100);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Extra operations detected", 1, operations.size());

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());

        Assert.assertEquals("Wrong port detected", server.getEndPoint().getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "handle", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", targetOperation.getRequest().getContentType());

        Assert.assertNotNull("No hashcode detected", introspector.getRequestInStreamHash());
        Assert.assertEquals("Wrong hashcode detected", Collections.singleton(expectedHash), introspector.getRequestInStreamHash());
    }

    @Test
    public void testURLMapping() {
        Iterator<ApplicationURLMapping> urlMappings = URLMappingsHelper.getApplicationURLMappings().iterator();
        Assert.assertTrue("should have elements", urlMappings.hasNext());

        ApplicationURLMapping urlMapping = urlMappings.next();
        Assert.assertEquals("invalid handler", Httpserver.Handler.class.getName(), urlMapping.getHandler());
        Assert.assertEquals("invalid http-method", "*", urlMapping.getMethod());
        Assert.assertEquals("invalid path", "/", urlMapping.getPath());

        Assert.assertTrue("should have elements", urlMappings.hasNext());

        urlMapping = urlMappings.next();
        Assert.assertEquals("invalid handler", Httpserver.Handler.class.getName(), urlMapping.getHandler());
        Assert.assertEquals("invalid http-method", "*", urlMapping.getMethod());
        Assert.assertEquals("invalid path", "/new", urlMapping.getPath());
    }

    @Trace(dispatcher = true)
    private void handle() throws URISyntaxException, IOException {
        URL url = server.getEndPoint().toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.connect();
        conn.getResponseCode();

    }

    private String handle1() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        URL url = server.getEndPoint().toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.setRequestMethod("GET");
        conn.setRequestProperty(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, headerValue);
        conn.setRequestProperty(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, headerValue);
        conn.setRequestProperty(GenericHelper.CSEC_PARENT_ID, headerValue);
        conn.connect();
        conn.getResponseCode();
        return  headerValue;
    }

    @Trace(dispatcher = true)
    private int handle2() throws URISyntaxException, IOException {
        URL url = server.getEndPoint().toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.setRequestMethod("POST");

        conn.connect();
        conn.getResponseCode();

        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        int hashCode = 0;
        String code;

        if((code = (br.readLine())) != null){
            hashCode = Integer.parseInt(code);
        }
        br.close();
        return hashCode;
    }
}
