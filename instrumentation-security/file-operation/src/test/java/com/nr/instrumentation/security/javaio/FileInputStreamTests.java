package com.nr.instrumentation.security.javaio;

import com.newrelic.agent.deps.com.google.common.io.Files;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.instrument.UnmodifiableClassException;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"java.io.FileInputStream_Instrumentation"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FileInputStreamTests {

    @BeforeClass
    public static void retransformRequiredClasses() throws UnmodifiableClassException {
        SecurityInstrumentationTestRunner.instrumentation.retransformClasses(FileInputStream.class);
    }

    @Test
    public void testFileInputStream() throws IOException {
        getFileInputStream("/tmp/test");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = (FileOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", operation.getFileName().get(0), "/tmp/test");
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
    }

    @Trace(dispatcher = true)
    private FileInputStream getFileInputStream(String filePath) throws IOException {
        Files.touch(new File(filePath));
        return new FileInputStream(filePath);
    }
}
