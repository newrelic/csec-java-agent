package com.nr.instrumentation.security.servlet6;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.nr.instrumentation.security.HttpServletServer;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "jakarta.servlet" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ServletInputStreamTest {

    @ClassRule
    public static HttpServletServer servlet = new HttpServletServer();

    @Test
    public void testRead() throws Exception {
        String expected = read();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("inputStream").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "multipart/form-data", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong data detected", expected, targetOperation.getRequest().getBody().toString());
    }


    @Test
    public void testReadLine() throws Exception {
        String expected = readLine();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("inputStream").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "multipart/form-data", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong data detected", expected, targetOperation.getRequest().getBody().toString());
    }

    @Test
    public void testReadLineWithOff() throws Exception {
        String expected = readLineWithOff();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("inputStream").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "multipart/form-data", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong data detected", expected, targetOperation.getRequest().getBody().toString());
    }

    @Trace(dispatcher = true)
    private String read() throws IOException, URISyntaxException {
        String method = "POST";
        String POST_PARAMS = "hook=read";
        makeRequest(method, POST_PARAMS, "read");
        return POST_PARAMS;
    }


    @Trace(dispatcher = true)
    private String readLine() throws IOException, URISyntaxException {
        String method = "POST";
        String POST_PARAMS = "hook=readLine";
        makeRequest(method, POST_PARAMS, "readLine");
        return POST_PARAMS;
    }

    @Trace(dispatcher = true)
    private String readLineWithOff() throws IOException, URISyntaxException {
        String method = "POST";
        String POST_PARAMS = "hook=readLine";
        makeRequest(method, POST_PARAMS, "readLine/withOff");
        return POST_PARAMS.substring(0,5);
    }

    private void makeRequest( String Method, final String POST_PARAMS, String path) throws URISyntaxException, IOException{

        URL u = servlet.getEndPoint("inputStream/"+ path).toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestMethod(Method);
        conn.setDoOutput(true);


        conn.setRequestMethod("POST");
        conn.setRequestProperty("Connection", "Keep-Alive");
        conn.setRequestProperty("Cache-Control", "no-cache");
        conn.setRequestProperty("Content-Type", "multipart/form-data");

        OutputStream os = conn.getOutputStream();
        os.write(POST_PARAMS.getBytes());
        os.flush();

        conn.connect();
        conn.getResponseCode();

    }
}
