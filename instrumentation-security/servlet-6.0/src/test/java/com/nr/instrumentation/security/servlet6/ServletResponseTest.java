package com.nr.instrumentation.security.servlet6;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "jakarta.servlet")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ServletResponseTest {
    @ClassRule
    public static HttpServletServer servlet = new HttpServletServer();

    @Test
    public void testGetOutputStream() throws Exception {
        int expectedHash = getOutputStream();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("response").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong hashcode detected", Collections.singleton(expectedHash), introspector.getResponseOutStreamHash());

    }

    @Test
    public void testGetWriter() throws Exception {
        int expectedHash = getWriter();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("response").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong hashcode detected", Collections.singleton(expectedHash), introspector.getResponseWriterHash());
    }

    @Trace(dispatcher = true)
    private int getOutputStream() throws IOException, URISyntaxException {

        String method = "POST";
        String POST_PARAMS = "hook=getOutputStream";
        return makeRequest(method, POST_PARAMS);

    }

    @Trace(dispatcher = true)
    private int getWriter() throws IOException, URISyntaxException {

        String method = "POST";
        String POST_PARAMS = "hook=getWriter";
        return makeRequest(method, POST_PARAMS);

    }

    private int makeRequest( String Method, final String POST_PARAMS) throws URISyntaxException, IOException{

        URL u = servlet.getEndPoint("response").toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestMethod(Method);
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();
        os.write(POST_PARAMS.getBytes());
        os.flush();
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
