package com.nr.agent.security.instrumentation.servlet24;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"javax.servlet", "com.newrelic.agent.security.instrumentation.servlet24"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ServletTest {

    @ClassRule
    public static HttpServletServer server = new HttpServletServer();
    private final String headerValue = String.valueOf(UUID.randomUUID());
    private final String fuzzHeader = "FILE_OPERATION--123:IAST:native:__K2PM0__:IAST:./tmp/file:IAST:SAFE:IAST:1:IAST:1:IAST:2aabd9833907ae4cde0120e4352c0da72d9e1acfcf298d6801b7120586d1df9d:IAST:02642fa0c3542fe5997eea314c0f5eec5b744ea83f168e998006111f9fa4fbd2";

    @Test
    public void testService() throws Exception {
        service();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());

        Assert.assertEquals("Wrong port detected", server.getEndPoint("").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", targetOperation.getRequest().getContentType());
    }
    @Test
    public void testServiceWithHeaders() throws Exception {
        serviceWithHeaders();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        
        Assert.assertEquals("Wrong port detected", server.getEndPoint("").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", targetOperation.getRequest().getContentType());
        assertCSECHeaders(targetOperation.getRequest().getHeaders());
        assertIASTIdentifier(introspector.getSecurityMetaData().getFuzzRequestIdentifier());
    }

    private void assertCSECHeaders(Map<String, String> headers){
        Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headerValue, headers.get(
                ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
        Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.toLowerCase()));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), fuzzHeader, headers.get(
                ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.toLowerCase()));
        Assert.assertTrue(String.format("Missing K2 header: %s", GenericHelper.CSEC_PARENT_ID), headers.containsKey(GenericHelper.CSEC_PARENT_ID.toLowerCase()));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", GenericHelper.CSEC_PARENT_ID), headerValue, headers.get(
                GenericHelper.CSEC_PARENT_ID.toLowerCase()));
    }
    @Trace(dispatcher = true)
    private void service() throws IOException, URISyntaxException {
        URL u = server.getEndPoint("test").toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.connect();
        conn.getResponseCode();
    }
    @Trace(dispatcher = true)
    private void serviceWithHeaders() throws IOException, URISyntaxException {
        URL u = server.getEndPoint("test").toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.setRequestProperty(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, headerValue);
        conn.setRequestProperty(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, fuzzHeader);
        conn.setRequestProperty(GenericHelper.CSEC_PARENT_ID, headerValue);
        conn.connect();
        conn.getResponseCode();
    }
    private void assertIASTIdentifier(K2RequestIdentifier identifier){
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
