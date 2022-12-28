package com.nr.instrumentation.security.javaio;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"java.io"})
public class FileSystemTests {
    private static final String FILE_NAME = "/tmp/test-" + UUID.randomUUID().toString();

    @BeforeClass
    public static void retransformRequiredClasses() {
        TestSetupBringUp.bringUp();
    }

    @Test
    public void testGetBooleanAttributes() throws IOException {
        getBooleanAttribute(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = null;
        for (AbstractOperation op : operations) {
            if (FILE_NAME.equals(((FileOperation) op).getFileName().get(0))) {
                targetOperation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Invalid executed parameters.", targetOperation.getFileName().get(0), FILE_NAME);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Trace(dispatcher = true)
    private void getBooleanAttribute(String filePath) throws IOException {
        new File(filePath).exists();
    }

    @AfterClass
    public static void tearDown() {
        new File(FILE_NAME).delete();
    }
}
