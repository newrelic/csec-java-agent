package com.nr.instrumentation.security.servlet5;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.nr.instrumentation.security.HttpServletServer;

import com.newrelic.api.agent.Trace;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "jakarta.servlet")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ServletRequestTest {

    @ClassRule
    public static HttpServletServer servlet = new HttpServletServer();


    @Test
    public void testGetInputStream() throws Exception {
        int expectedHash = getInputStream();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("request").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong hashcode detected", expectedHash, introspector.getRequestInStreamHash());

    }

    @Test
    public void testGetReader() throws Exception {
        int expectedHash = getReader();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("request").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong hashcode detected", expectedHash, introspector.getRequestReaderHash());

    }

    @Test
    public void testGetParameter() throws Exception {
        String expectedParam = getParameter();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("request").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertFalse("No param detected", targetOperation.getRequest().getParameterMap().isEmpty());
        Assert.assertEquals("Wrong Param detected", expectedParam, new ObjectMapper().writeValueAsString(targetOperation.getRequest().getParameterMap()));
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());

    }

    @Test
    public void testGetParameterValues() throws Exception {
        String expectedParam = getParameterValues();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("request").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertFalse("No param detected", targetOperation.getRequest().getParameterMap().isEmpty());
        Assert.assertEquals("Wrong Param detected", expectedParam, new ObjectMapper().writeValueAsString(targetOperation.getRequest().getParameterMap()));
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());

    }

    @Test
    public void testGetParameterMap() throws Exception {
        String expectedParam = getParameterMap();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("request").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertFalse("No param detected", targetOperation.getRequest().getParameterMap().isEmpty());
        Assert.assertEquals("Wrong Param detected", expectedParam, new ObjectMapper().writeValueAsString(targetOperation.getRequest().getParameterMap()));
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());

    }

    @Trace(dispatcher = true)
    private int getInputStream() throws IOException, URISyntaxException {
        String method = "POST";
        String POST_PARAMS = "hook=getInputStream";
        return makeRequest(method , POST_PARAMS);

    }

    @Trace(dispatcher = true)
    private int getReader() throws IOException, URISyntaxException {
        String method = "POST";
        String POST_PARAMS = "hook=getReader";
        return makeRequest(method , POST_PARAMS);
    }

    @Trace(dispatcher = true)
    private String getParameter() throws IOException, URISyntaxException {
        String method = "POST";
        String POST_PARAMS = "hook=getInputStream";
        makeRequest(method , POST_PARAMS);
        return extractParam(POST_PARAMS);

    }

    @Trace(dispatcher = true)
    private String  getParameterValues() throws IOException, URISyntaxException {
        String method = "POST";
        String POST_PARAMS = "hook=getParameterValues&val=test1&val=test2";
        makeRequest(method , POST_PARAMS);
        return extractParam(POST_PARAMS);

    }


    @Trace(dispatcher = true)
    private String getParameterMap() throws IOException, URISyntaxException {
        String method = "POST";
        String POST_PARAMS = "hook=getParameterMap&val=test";
        makeRequest(method , POST_PARAMS);
        return extractParam(POST_PARAMS);

    }

    private int makeRequest( String Method, final String POST_PARAMS) throws URISyntaxException, IOException{

        URL u = servlet.getEndPoint("request").toURL();
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

    private String extractParam(String params) throws JsonProcessingException {

        String[] paramsArray = params.split("&");
        Map<String, List<String>> map = new HashMap<>();

        for (String allParam: paramsArray) {
            String[] paramList = allParam.split("=");

            if(paramList.length == 2) {
                map.putIfAbsent(paramList[0], new ArrayList<>());
                map.get(paramList[0]).add(paramList[1]);
            }
        }

        return new ObjectMapper().writeValueAsString(map);
    }
}
