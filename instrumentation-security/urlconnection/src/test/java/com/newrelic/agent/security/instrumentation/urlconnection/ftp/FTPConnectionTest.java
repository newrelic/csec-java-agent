package com.newrelic.agent.security.instrumentation.urlconnection.ftp;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.FtpServerClient;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import sun.net.www.protocol.ftp.FtpURLConnection;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.newrelic.agent.security.instrumentation.urlconnection"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FTPConnectionTest {
    private static final String FTP_USER = "user";
    private static final String FTP_PASSWORD = "password";
    private static final String FTP_DIR = "/data";

    @ClassRule
    public static FtpServerClient ftpClient = new FtpServerClient("localhost", 0, FTP_USER, FTP_PASSWORD, FTP_DIR);

    @Trace(dispatcher = true)
    private static void callConnect(String ftpUrl) throws IOException {
        URLConnection urlConnection = new URL(ftpUrl).openConnection();
        urlConnection.connect();
    }

    @Trace(dispatcher = true)
    private static void callConnect1(String ftpUrl) throws IOException {
        FtpURLConnection urlConnection = (FtpURLConnection) new URL(ftpUrl).openConnection();
        urlConnection.connect();
    }

    @Trace(dispatcher = true)
    private static void callGetInputStream(String ftpUrl) throws IOException {
        URLConnection urlConnection = new URL(ftpUrl).openConnection();
        urlConnection.getInputStream();
    }

    @Trace(dispatcher = true)
    private static void callGetInputStreamByGetContent(String ftpUrl) throws IOException {
        URLConnection urlConnection = new URL(ftpUrl).openConnection();
        urlConnection.getContent();
    }

    @Trace(dispatcher = true)
    private static void callGetInputStreamByGetContent1(String ftpUrl) throws IOException {
        URLConnection urlConnection = new URL(ftpUrl).openConnection();
        urlConnection.getContent(new Class[]{String.class});
    }

    @Trace(dispatcher = true)
    private static void callGetOutputStream(String ftpUrl) throws IOException {
        URLConnection urlConnection = new URL(ftpUrl).openConnection();
        urlConnection.setDoOutput(true);

        try (OutputStream output = urlConnection.getOutputStream()) {
            System.out.println(output);
        }
    }

    @Before
    public void setup() throws IOException {
        ftpClient.open();
    }

    @After
    public void teardown() throws IOException {
        ftpClient.close();
    }

    @Test
    public void testFtpConnect() throws IOException {
        String ftpUrl = ftpClient.getURL();

        callConnect(ftpUrl);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", ftpUrl, operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", FtpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "connect", operation.getMethodName());
    }

    @Test
    public void testFtpConnect1() throws IOException {
        String ftpUrl = ftpClient.getURL();

        callConnect1(ftpUrl);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", ftpUrl, operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", FtpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "connect", operation.getMethodName());
    }

    @Test
    public void testFtpGetInputStream() throws IOException {
        String ftpUrl = ftpClient.getURL();

        callGetInputStream(ftpUrl);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", ftpUrl, operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", FtpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
    }

    @Test
    public void testFtpGetInputStreamByGetContent() throws IOException {
        String ftpUrl = ftpClient.getURL();

        callGetInputStreamByGetContent(ftpUrl);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", ftpUrl, operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", FtpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
    }

    @Test
    public void testFtpGetInputStreamByGetContent1() throws IOException {
        String ftpUrl = ftpClient.getURL();

        callGetInputStreamByGetContent1(ftpUrl);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", ftpUrl, operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", FtpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
    }

    @Test
    public void testFtpGetInputStreamByConGetContent() throws IOException {
        String ftpUrl = ftpClient.getURL();

        callGetInputStreamByConGetContent(ftpUrl);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), ftpUrl);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", FtpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    private void callGetInputStreamByConGetContent(String endpoint) throws IOException {
        new URL(endpoint).openConnection().getContent();
    }

    @Test
    public void testFtpGetInputStreamByConGetContent1() throws IOException {
        String ftpUrl = ftpClient.getURL();

        callGetInputStreamByConGetContent1(ftpUrl);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), ftpUrl);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", FtpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    private void callGetInputStreamByConGetContent1(String endpoint) throws IOException {
        new URL(endpoint).openConnection().getContent(new Class[]{String.class});
    }

    @Test
    public void testFtpGetInputStreamByOpenStream() throws IOException {
        String ftpUrl = ftpClient.getURL();

        callGetInputStreamByOpenStream(ftpUrl);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), ftpUrl);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", FtpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    private void callGetInputStreamByOpenStream(String endpoint) throws IOException {
        new URL(endpoint).openStream();
    }

    @Test
    public void testFtpGetOutputStream() throws IOException {
        String ftpUrl = ftpClient.getURL()+"/temp.txt";

        callGetOutputStream(ftpUrl);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", ftpUrl, operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", FtpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getOutputStream", operation.getMethodName());
    }
}
