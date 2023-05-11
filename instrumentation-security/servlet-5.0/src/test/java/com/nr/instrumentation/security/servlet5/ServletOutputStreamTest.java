package com.nr.instrumentation.security.servlet5;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.nr.instrumentation.security.HttpServletServer;
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
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "jakarta.servlet" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ServletOutputStreamTest {

    @ClassRule
    public static HttpServletServer servlet = new HttpServletServer();

    @Test
    public void testWrite() throws URISyntaxException, IOException {
        String expected = write();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Request Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));
        Assert.assertEquals("Wrong Response Content-type detected", "multipart/form-data", targetOperation.getResponse().getResponseContentType());

    }

    @Test
    public void testPrintString() throws URISyntaxException, IOException {
        String expected = printString();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong request Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));

    }

    @Test
    public void testPrintBoolean() throws URISyntaxException, IOException {
        boolean expected = printBoolean();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());

        boolean resBody = Boolean.parseBoolean(String.valueOf(targetOperation.getResponse().getResponseBody()));
        Assert.assertEquals("Wrong response detected", expected, resBody);
    }

    @Test
    public void testPrintChar() throws URISyntaxException, IOException {
        char expected = printChar();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());

        char resBody = String.valueOf(targetOperation.getResponse().getResponseBody()).charAt(0);
        Assert.assertEquals("Wrong response detected", expected, resBody);

    }

    @Test
    public void testPrintInt() throws URISyntaxException, IOException {
        int expected = printInt();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());

        int resBody = Integer.parseInt(String.valueOf(targetOperation.getResponse().getResponseBody()));
        Assert.assertEquals("Wrong response detected", expected, resBody);
    }

    @Test
    public void testPrintLong() throws URISyntaxException, IOException {
        long expected = printLong();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());

        long resBody = Long.parseLong(String.valueOf(targetOperation.getResponse().getResponseBody()));
        Assert.assertEquals("Wrong response detected", expected, resBody);
    }

    @Test
    public void testPrintFloat() throws URISyntaxException, IOException {
        float expected = printFloat();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());

        float resBody = Float.parseFloat(String.valueOf(targetOperation.getResponse().getResponseBody()));
        Assert.assertEquals("Wrong response detected",expected, resBody, 0.0f);
    }

    @Test
    public void testPrintDouble() throws URISyntaxException, IOException {
        double expected = printDouble();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());

        double resBody = Double.parseDouble(String.valueOf(targetOperation.getResponse().getResponseBody()));
        Assert.assertEquals("Wrong response detected", expected, resBody, 0.0d);
    }

    @Test
    public void testPrintln() throws URISyntaxException, IOException {
        String expected = println();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));

    }

    @Test
    public void testPrintlnString() throws URISyntaxException, IOException {
        String expected = printlnString();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));

    }

    @Test
    public void testPrintlnBoolean() throws URISyntaxException, IOException {
        String expected = printlnBoolean();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));

    }

    @Test
    public void testPrintlnChar() throws URISyntaxException, IOException {
        String expected = printlnChar();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));

    }

    @Test
    public void testPrintlnInt() throws URISyntaxException, IOException {
        String expected = printlnInt();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));

    }

    @Test
    public void testPrintlnLong() throws URISyntaxException, IOException {
        String expected = printlnLong();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));
    }

    @Test
    public void testPrintlnFloat() throws URISyntaxException, IOException {
        String expected = printlnFloat();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));
    }

    @Test
    public void testPrintlnDouble() throws URISyntaxException, IOException {
        String expected = printlnDouble();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", servlet.getEndPoint("outputStream/print").getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "service", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "application/x-www-form-urlencoded", targetOperation.getRequest().getContentType());
        Assert.assertEquals("Wrong URL detected", "/TestUrl", targetOperation.getRequest().getUrl());
        Assert.assertEquals("Wrong response detected", expected, String.valueOf(targetOperation.getResponse().getResponseBody()));
    }
    @Trace(dispatcher = true)
    private String write() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=no-param";
        return makeRequest(method, POST_PARAMS, "write");
    }



    @Trace(dispatcher = true)
    private String printString() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=String";
        return makeRequest(method, POST_PARAMS, "print");
    }

    @Trace(dispatcher = true)
    private boolean printBoolean() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=boolean";
        return Boolean.parseBoolean(makeRequest(method, POST_PARAMS, "print"));
    }
    @Trace(dispatcher = true)
    private char printChar() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=char";
        return makeRequest(method, POST_PARAMS, "print").charAt(0);
    }
    @Trace(dispatcher = true)
    private int printInt() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=int";
        return Integer.parseInt(makeRequest(method, POST_PARAMS, "print"));
    }
    @Trace(dispatcher = true)
    private long printLong() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=long";
        return Long.parseLong(makeRequest(method, POST_PARAMS, "print"));
    }
    @Trace(dispatcher = true)
    private float printFloat() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=float";
        return Float.parseFloat(makeRequest(method, POST_PARAMS, "print"));
    }
    @Trace(dispatcher = true)
    private double printDouble() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=double";
        return Double.parseDouble(makeRequest(method, POST_PARAMS, "print"));
    }

    @Trace(dispatcher = true)
    private String println() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=null";
        return makeRequest(method, POST_PARAMS, "println")+"\n";
    }
    @Trace(dispatcher = true)
    private String printlnString() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=String";
        return makeRequest(method, POST_PARAMS, "println")+"\n";
    }

    @Trace(dispatcher = true)
    private String printlnBoolean() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=boolean";
        return makeRequest(method, POST_PARAMS, "println")+"\n";
    }
    @Trace(dispatcher = true)
    private String printlnChar() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=char";
        return makeRequest(method, POST_PARAMS, "println")+"\n";
    }
    @Trace(dispatcher = true)
    private String printlnInt() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=int";
        return makeRequest(method, POST_PARAMS, "println")+"\n";
    }
    @Trace(dispatcher = true)
    private String printlnLong() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=long";
        return makeRequest(method, POST_PARAMS, "println")+"\n";
    }
    @Trace(dispatcher = true)
    private String printlnFloat() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=float";
        return makeRequest(method, POST_PARAMS, "println")+"\n";
    }
    @Trace(dispatcher = true)
    private String printlnDouble() throws URISyntaxException, IOException {
        String method = "POST";
        String POST_PARAMS = "type=double";
        return makeRequest(method, POST_PARAMS, "println")+"\n";
    }

    private String makeRequest( String Method, final String POST_PARAMS, String path) throws URISyntaxException, IOException{

        URL u = servlet.getEndPoint("outputStream/" + path).toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestMethod(Method);
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();
        os.write(POST_PARAMS.getBytes());
        os.flush();

        conn.connect();
        conn.getResponseCode();

        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String returnVal = StringUtils.EMPTY;
        String code;
        if((code = (br.readLine())) != null){
            returnVal = code;
        }
        br.close();

        return returnVal;
    }
}
