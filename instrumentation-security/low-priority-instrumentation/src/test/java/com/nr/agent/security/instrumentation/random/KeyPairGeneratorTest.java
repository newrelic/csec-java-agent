package com.nr.agent.security.instrumentation.random;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.HashCryptoOperation;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.newrelic.agent.security.instrumentation.random" })
public class KeyPairGeneratorTest {

    @Test
    public void testGetInstance() throws NoSuchAlgorithmException, JsonProcessingException, NoSuchProviderException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        HashCryptoOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof HashCryptoOperation)
                operation = (HashCryptoOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.CRYPTO, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", "KEYPAIRGENERATOR", operation.getEventCategory());
        Assert.assertEquals("Invalid executed method name.", "getInstance", operation.getMethodName());
        Assert.assertEquals("Invalid algo name.", "RSA", operation.getName());
        Assert.assertEquals("Invalid provider.", "", operation.getProvider());
    }

    @Test
    public void testGetInstance1() throws NoSuchPaddingException, NoSuchAlgorithmException, JsonProcessingException, NoSuchProviderException {
        KeyPairGenerator sr = KeyPairGenerator.getInstance("RSA");
        Provider pd = sr.getProvider();
        String algo = sr.getAlgorithm();
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algo, pd);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        HashCryptoOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof HashCryptoOperation) {
                HashCryptoOperation tempOp = (HashCryptoOperation) op;
                if ("SunRsaSign".equals(tempOp.getProvider())) {
                    operation =tempOp;
                }
            }
        }
        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.CRYPTO, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", "KEYPAIRGENERATOR", operation.getEventCategory());
        Assert.assertEquals("Invalid executed method name.", "getInstance", operation.getMethodName());
        Assert.assertEquals("Invalid algo name.", "RSA", operation.getName());
        Assert.assertEquals("Invalid provider.", "SunRsaSign", operation.getProvider());
    }

    @Test
    public void testGetInstance2() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator sr = KeyPairGenerator.getInstance("RSA");
        Provider pd = sr.getProvider();
        String algo = sr.getAlgorithm();
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", pd.getName());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        HashCryptoOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof HashCryptoOperation)
                operation = (HashCryptoOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.CRYPTO, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", "KEYPAIRGENERATOR", operation.getEventCategory());
        Assert.assertEquals("Invalid executed method name.", "getInstance", operation.getMethodName());
        Assert.assertEquals("Invalid algo name.", "RSA", operation.getName());
        Assert.assertEquals("Invalid provider.", "SunRsaSign", operation.getProvider());
    }
}
