package com.nr.agent.security.instrumentation.servlet24;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SecureCookieOperationSet;
import com.newrelic.api.agent.security.schema.operation.TrustBoundaryOperation;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.servlet", "com.newrelic.agent.security.instrumentation.servlet24" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HttpSessionTest {
    @ClassRule
    public static HttpServletServer server = new HttpServletServer();

    @Test
    public void testSessionSetAttribute() throws IOException, URISyntaxException {
        makeRequest("set");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertTrue("Unexpected operation count detected", operations.size() == 2 || operations.size() == 3);
        TrustBoundaryOperation targetOperation = null;
        int i=0;
        for (AbstractOperation operation : operations) {
            if (operation instanceof TrustBoundaryOperation) {
                targetOperation = (TrustBoundaryOperation) operation;
                if(i==0){
                    Assert.assertNotNull("No target operation detected", targetOperation);
                    Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.TRUSTBOUNDARY, targetOperation.getCaseType());
                    Assert.assertEquals("Wrong key detected", "key", targetOperation.getKey());
                    Assert.assertEquals("Wrong value detected", "value", targetOperation.getValue());
                }
                else if(i==1){
                    Assert.assertNotNull("No target operation detected", targetOperation);
                    Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.TRUSTBOUNDARY, targetOperation.getCaseType());
                    Assert.assertEquals("Wrong key detected", "key", targetOperation.getKey());
                    Assert.assertEquals("Wrong value detected", "value", targetOperation.getValue());
                }
                i++;
            }
        }
    }

    @Test
    public void testSessionPutValue() throws IOException, URISyntaxException {
        makeRequest("put");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertTrue("Unexpected operation count detected", operations.size() == 2 || operations.size() == 3);
        TrustBoundaryOperation targetOperation = null;
        for (AbstractOperation operation : operations) {
            if (operation instanceof TrustBoundaryOperation)
                targetOperation = (TrustBoundaryOperation) operation;

            Assert.assertNotNull("No target operation detected", targetOperation);
            Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.TRUSTBOUNDARY, targetOperation.getCaseType());
            Assert.assertEquals("Wrong key detected", "key1", targetOperation.getKey());
            Assert.assertEquals("Wrong value detected", "value1", targetOperation.getValue());
        }

    }

    @Test
    public void testAddCookie() throws IOException, URISyntaxException {
        makeRequest("securecookie");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertTrue("Unexpected operation count detected", operations.size() == 1 || operations.size() == 2);
        SecureCookieOperationSet targetOperation = null;
        targetOperation = verifySecureCookieOp(operations);

        Assert.assertTrue(!targetOperation.getOperations().isEmpty());
        Iterator<SecureCookieOperationSet.SecureCookieOperation> secureCookieOps = targetOperation.getOperations().iterator();
        Assert.assertTrue(secureCookieOps.hasNext());

        SecureCookieOperationSet.SecureCookieOperation secureCookieOp = secureCookieOps.next();
        verifySecureCookie(secureCookieOp, "key", false, true);
    }

    @Test
    public void testAddCookie1() throws IOException, URISyntaxException {
        makeRequest("cookie");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        SecureCookieOperationSet targetOperation = verifySecureCookieOp(operations);
        Assert.assertTrue(!targetOperation.getOperations().isEmpty());

        Iterator<SecureCookieOperationSet.SecureCookieOperation> secureCookieOps = targetOperation.getOperations().iterator();
        Assert.assertTrue(secureCookieOps.hasNext());

        SecureCookieOperationSet.SecureCookieOperation secureCookieOp = secureCookieOps.next();
        verifySecureCookie(secureCookieOp, "key", false, false);
    }

    @Test
    public void testAddSecureCookies() throws IOException, URISyntaxException {
        makeRequest("secure_cookies");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        SecureCookieOperationSet targetOperation = verifySecureCookieOp(operations);
        Assert.assertEquals(2, targetOperation.getOperations().size());

        for (SecureCookieOperationSet.SecureCookieOperation secureCookieOp : targetOperation.getOperations()) {
            if (secureCookieOp.getName().equals("secure-cookie-1")) {
                verifySecureCookie(secureCookieOp, "secure-cookie-1", false, true);
            } else {
                verifySecureCookie(secureCookieOp, "secure-cookie-2", true, true);
            }
        }
    }

    @Test
    public void testAddInSecureCookies() throws IOException, URISyntaxException {
        makeRequest("insecure_cookies");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        SecureCookieOperationSet targetOperation = verifySecureCookieOp(operations);
        Assert.assertEquals(2, targetOperation.getOperations().size());

        for (SecureCookieOperationSet.SecureCookieOperation secureCookieOp : targetOperation.getOperations()) {
            if (secureCookieOp.getName().equals("insecure-cookie-1")) {
                verifySecureCookie(secureCookieOp, "insecure-cookie-1", false, false);
            } else {
                verifySecureCookie(secureCookieOp, "insecure-cookie-2", false, false);
            }
        }
    }

    @Test
    public void testAddMultiSecureCookies() throws IOException, URISyntaxException {
        makeRequest("cookies");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        SecureCookieOperationSet targetOperation = verifySecureCookieOp(operations);
        Assert.assertEquals(2, targetOperation.getOperations().size());

        for (SecureCookieOperationSet.SecureCookieOperation secureCookieOp : targetOperation.getOperations()) {
            if (secureCookieOp.getName().equals("insecure-cookie")) {
                verifySecureCookie(secureCookieOp, "insecure-cookie", false, false);
            } else {
                verifySecureCookie(secureCookieOp, "secure-cookie", false, true);
            }
        }
    }

    @Test
    public void testSingleCookie() throws IOException, URISyntaxException {
        makeRequest("single-cookie");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        SecureCookieOperationSet targetOperation = verifySecureCookieOp(operations);
        Assert.assertEquals(1, targetOperation.getOperations().size());

        Iterator<SecureCookieOperationSet.SecureCookieOperation> secureCookieOps = targetOperation.getOperations().iterator();

        Assert.assertTrue(secureCookieOps.hasNext());
        SecureCookieOperationSet.SecureCookieOperation secureCookieOp = secureCookieOps.next();
        verifySecureCookie(secureCookieOp, "cookie", true, true);
    }

    private void makeRequest(String path) throws URISyntaxException, IOException{
        URL u = server.getEndPoint("session/"+path).toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setDoOutput(true);
        conn.setRequestProperty("Connection", "Keep-Alive");
        conn.setRequestProperty("Cache-Control", "no-cache");
        conn.setRequestProperty("Content-Type", "multipart/form-data");

        conn.connect();
        conn.getResponseCode();
    }

    private SecureCookieOperationSet verifySecureCookieOp(List<AbstractOperation> operations) {
        SecureCookieOperationSet targetOperation = null;
        for (AbstractOperation operation : operations) {
            if (operation instanceof SecureCookieOperationSet) {
                targetOperation = (SecureCookieOperationSet) operation;
            }
        }

        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong method detected", "addCookie", targetOperation.getMethodName());
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.SECURE_COOKIE, targetOperation.getCaseType());
        Assert.assertTrue("isLowSeverityHook should be true", targetOperation.isLowSeverityHook());
        return targetOperation;
    }

    private void verifySecureCookie(SecureCookieOperationSet.SecureCookieOperation secureCookieOp, String key, boolean isHttpOnly, boolean isSecure) {
        Assert.assertEquals("Wrong cookie key detected", key, secureCookieOp.getName());
        Assert.assertEquals("Wrong cookie value detected", "value", secureCookieOp.getValue());
        Assert.assertEquals(String.format("isHttpOnly should be %s", isHttpOnly), isHttpOnly, secureCookieOp.isHttpOnly());
        Assert.assertEquals(String.format("isSecure should be %s", isSecure), isSecure, secureCookieOp.isSecure());
        Assert.assertTrue(String.format("isSameSiteStrict should be %s", true), secureCookieOp.isSameSiteStrict());
    }
}
