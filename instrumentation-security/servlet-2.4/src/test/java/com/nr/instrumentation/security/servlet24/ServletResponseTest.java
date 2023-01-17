package com.nr.instrumentation.security.servlet24;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.nr.instrumentation.security.HttpServletServer;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "javax.servlet")
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
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("response").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong hashcode detected", expectedHash, introspector.getResponseOutStreamHash());

    }

    @Test
    public void testGetWriter() throws Exception {
        int expectedHash = getWriter();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("response").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong hashcode detected", expectedHash, introspector.getResponseWriterHash());
    }

    @Trace(dispatcher = true)
    private int getOutputStream() throws IOException, URISyntaxException {

        String method = "POST";
        String POST_PARAMS = "hook=getOutputStream";
        int hashCode = makeRequest(method, POST_PARAMS);
        return hashCode;

    }

    @Trace(dispatcher = true)
    private int getWriter() throws IOException, URISyntaxException {

        String method = "POST";
        String POST_PARAMS = "hook=getWriter";
        int hashCode = makeRequest(method, POST_PARAMS);
        return hashCode;

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
