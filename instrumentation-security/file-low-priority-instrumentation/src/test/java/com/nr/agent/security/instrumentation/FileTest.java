package com.nr.agent.security.instrumentation;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.security.test.marker.*;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.newrelic.agent.security.instrumentation.random", "java.io"})
@Category({ Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class FileTest {
    private static final String FILE_NAME = "/tmp/test-" + UUID.randomUUID();

    @BeforeClass
    public static void retransformRequiredClasses() {
        TestSetupBringUp.bringUp();
    }

    @Test
    public void testExists() {
        exists();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected", operations.isEmpty());
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "exists", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
        Assert.assertTrue("GetBooleanAttributesCall should be true", targetOperation.isGetBooleanAttributesCall());
    }

    @Test
    public void testExists1() {
        exists1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations should detected", operations.isEmpty());

    }

    @Trace(dispatcher = true)
    private void exists() {
        new File(FILE_NAME).exists();
    }

    @Trace(dispatcher = true)
    private void exists1() {
        new File("").exists();
    }
}
