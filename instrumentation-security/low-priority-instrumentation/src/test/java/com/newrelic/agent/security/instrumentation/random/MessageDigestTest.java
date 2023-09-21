package com.newrelic.agent.security.instrumentation.random;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.HashCryptoOperation;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.crypto.NoSuchPaddingException;
import java.lang.instrument.UnmodifiableClassException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.newrelic.agent.security.instrumentation.security.random" })
public class MessageDigestTest {

    @BeforeClass
    public static void testBringUp() throws UnmodifiableClassException {
        SecurityInstrumentationTestRunner.instrumentation.retransformClasses(MessageDigest.class);
    }

    @Test
    public void testGetInstance() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        HashCryptoOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof HashCryptoOperation)
                operation = (HashCryptoOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.HASH, operation.getCaseType());
        Assert.assertNull("Invalid event category.", operation.getEventCategory());
        Assert.assertEquals("Invalid executed method name.", "getInstance", operation.getMethodName());
        Assert.assertEquals("Invalid algo name.", "SHA-256", operation.getName());
        Assert.assertEquals("Invalid provider.", "", operation.getProvider());
    }

    @Test
    public void testGetInstance1() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest sr = MessageDigest.getInstance("SHA-256");
        Provider pd = sr.getProvider();
        String algo = sr.getAlgorithm();
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", pd.getName());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        HashCryptoOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof HashCryptoOperation) {
                HashCryptoOperation tempOp = (HashCryptoOperation) op;
                if (tempOp.getProvider() == "SUN") {
                    operation =tempOp;
                }
            }
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.HASH, operation.getCaseType());
        Assert.assertNull("Invalid event category.", operation.getEventCategory());
        Assert.assertEquals("Invalid executed method name.", "getInstance", operation.getMethodName());
        Assert.assertEquals("Invalid algo name.", "SHA-256", operation.getName());
        Assert.assertEquals("Invalid provider.", "SUN", operation.getProvider());
    }

    @Test
    public void testGetInstance2() throws NoSuchAlgorithmException {
        MessageDigest sr = MessageDigest.getInstance("SHA-256");
        Provider pd = sr.getProvider();
        String algo = sr.getAlgorithm();
        MessageDigest messageDigest = MessageDigest.getInstance(algo, pd);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        HashCryptoOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof HashCryptoOperation)
                operation = (HashCryptoOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.HASH, operation.getCaseType());
        Assert.assertNull("Invalid event category.", operation.getEventCategory());
        Assert.assertEquals("Invalid executed method name.", "getInstance", operation.getMethodName());
        Assert.assertEquals("Invalid algo name.", "SHA-256", operation.getName());
        Assert.assertEquals("Invalid provider.", "Sun", operation.getProvider());
    }
}
