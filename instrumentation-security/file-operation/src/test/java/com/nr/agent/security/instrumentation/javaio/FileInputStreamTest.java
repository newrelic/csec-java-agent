package com.nr.agent.security.instrumentation.javaio;

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
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"java.io", "java.nio"})
public class FileInputStreamTest {

    private static final String FILE_NAME = "/tmp/test-" + UUID.randomUUID().toString();

    @BeforeClass
    public static void retransformRequiredClasses() {
        TestSetupBringUp.bringUp();
    }

    @Test
    public void testFileInputStream() throws IOException {
        getFileInputStream(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("Expected more operations than the actual detected", operations.size() > 2);
        FileOperation targetOperation1 = (FileOperation) operations.get(0);
        FileOperation targetOperation2 = (FileOperation) operations.get(1);
        FileOperation targetOperation3 = (FileOperation) operations.get(2);

        Assert.assertEquals("Invalid method Name", "mkdirs", targetOperation1.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", "/tmp", targetOperation1.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation1.getCaseType());

        Assert.assertEquals("Invalid method Name", "createNewFile", targetOperation2.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation2.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation2.getCaseType());

        Assert.assertEquals("Invalid method Name", "open", targetOperation3.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation3.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation3.getCaseType());
    }

    @Trace(dispatcher = true)
    private FileInputStream getFileInputStream(String filePath) throws IOException {
        new File(filePath).getParentFile().mkdirs();
        new File(filePath).createNewFile();
        return new FileInputStream(filePath);
    }

    @AfterClass
    public static void tearDown() {
        new File(FILE_NAME).delete();
    }
}
