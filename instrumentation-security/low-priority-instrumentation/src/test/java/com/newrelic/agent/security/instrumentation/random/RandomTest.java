package com.newrelic.agent.security.instrumentation.random;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.HashCryptoOperation;
import com.newrelic.api.agent.security.schema.operation.RandomOperation;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.instrument.UnmodifiableClassException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.newrelic.agent.security.instrumentation.security.random")
public class RandomTest {
    private static final String SECURE_RANDOM = "SECURERANDOM";
    private static final String WEAK_RANDOM = "WEAKRANDOM";

    @BeforeClass
    public static void testBringUp() throws UnmodifiableClassException {
        SecurityInstrumentationTestRunner.instrumentation.retransformClasses(ThreadLocalRandom.class);
    }

    @Test
    public void testNextInt() throws JsonProcessingException {
        try{
            Random rand = new FixedSecureRandom(new byte[]{});
            rand.nextInt();
        } catch (Exception e) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        RandomOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof RandomOperation)
                operation = (RandomOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.RANDOM, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", SECURE_RANDOM, operation.getEventCatgory());
        Assert.assertEquals("Invalid executed method name.", "nextInt", operation.getMethodName());
    }

    @Test
    public void testNextInt1() throws JsonProcessingException {
        try{
            Random rand = ThreadLocalRandom.current();
            rand.nextInt(2);
        } catch (Exception e) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        RandomOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof RandomOperation)
                operation = (RandomOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.RANDOM, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", WEAK_RANDOM, operation.getEventCatgory());
        Assert.assertEquals("Invalid executed method name.", "nextInt", operation.getMethodName());
    }

    @Test
    public void testNextLong() throws JsonProcessingException {
        try{
            Random rand = new FixedSecureRandom(new byte[]{});
            rand.nextLong();
        } catch (Exception e) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        RandomOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof RandomOperation)
                operation = (RandomOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.RANDOM, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", SECURE_RANDOM, operation.getEventCatgory());
        Assert.assertEquals("Invalid executed method name.", "nextLong", operation.getMethodName());
    }

    @Test
    public void testNextFloat() throws JsonProcessingException {
        try{
            Random rand = ThreadLocalRandom.current();
            rand.nextFloat();
        } catch (Exception e) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        RandomOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof RandomOperation)
                operation = (RandomOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.RANDOM, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", WEAK_RANDOM, operation.getEventCatgory());
        Assert.assertEquals("Invalid executed method name.", "nextFloat", operation.getMethodName());
    }

    @Test
    public void testNextDouble() throws JsonProcessingException {
        try{
            Random rand = ThreadLocalRandom.current();
            rand.nextDouble();
        } catch (Exception e) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        RandomOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof RandomOperation)
                operation = (RandomOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.RANDOM, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", WEAK_RANDOM, operation.getEventCatgory());
        Assert.assertEquals("Invalid executed method name.", "nextDouble", operation.getMethodName());
    }

    @Test
    public void testNextBoolean() throws JsonProcessingException {
        try{
            Random rand = ThreadLocalRandom.current();
            rand.nextBoolean();
        } catch (Exception e) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        RandomOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof RandomOperation)
                operation = (RandomOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.RANDOM, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", WEAK_RANDOM, operation.getEventCatgory());
        Assert.assertEquals("Invalid executed method name.", "nextBoolean", operation.getMethodName());
    }

    @Test
    public void testNextGaussian() throws JsonProcessingException {
        try{
            Random rand = ThreadLocalRandom.current();
            rand.nextGaussian();
        } catch (Exception e) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        RandomOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof RandomOperation)
                operation = (RandomOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.RANDOM, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", WEAK_RANDOM, operation.getEventCatgory());
        Assert.assertEquals("Invalid executed method name.", "nextGaussian", operation.getMethodName());
    }

    @Test
    public void testNextBytes() throws JsonProcessingException {
        try{
            Random rand = new FixedSecureRandom(new byte[]{});
            rand.nextBytes(new byte[]{});
        } catch (Exception e) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        RandomOperation operation = null;
        for (AbstractOperation op : operations) {
            if (op instanceof RandomOperation)
                operation = (RandomOperation) op;
        }

        Assert.assertEquals("Invalid event case type.", VulnerabilityCaseType.RANDOM, operation.getCaseType());
        Assert.assertEquals("Invalid event category.", SECURE_RANDOM, operation.getEventCatgory());
        Assert.assertEquals("Invalid executed method name.", "nextBytes", operation.getMethodName());
    }
}
