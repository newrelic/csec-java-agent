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
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"java.io", "java.nio"})
public class FileOutputStreamTest {
    private static final String FILE_NAME = "/tmp/test-" + UUID.randomUUID().toString();

    @BeforeClass
    public static void retransformRequiredClasses() {
        TestSetupBringUp.bringUp();
    }

    @Test
    public void testFileOutputStream() throws IOException {
        getFileOutputStream(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "open", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
        Assert.assertEquals("Invalid operation category", FileOperation.WRITE_OP, targetOperation.getCategory());
    }

    @Trace(dispatcher = true)
    private FileOutputStream getFileOutputStream( String filePath) throws IOException {
        return new FileOutputStream(filePath);
    }

    @AfterClass
    public static void tearDown() {
        new File(FILE_NAME).delete();
    }
}
