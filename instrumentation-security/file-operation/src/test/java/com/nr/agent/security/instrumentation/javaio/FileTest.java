package com.nr.agent.security.instrumentation.javaio;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"java.io", "java.nio"})
@Category({ Java17IncompatibleTest.class })
public class FileTest {
    private static final String FILE_NAME = "/tmp/test-" + UUID.randomUUID();

    @BeforeClass
    public static void retransformRequiredClasses() {
        TestSetupBringUp.bringUp();
    }

    @Test
    @Ignore ("This construct is supported in file-low-priority-instrumentation module")
    public void testGetBooleanAttributes() throws IOException {
        exists(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "exists", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testCreateNewFile() throws IOException {
        createNewFile(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "createNewFile", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testDelete() throws IOException {
        delete(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "delete", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testDeleteOnExit() throws IOException {
        deleteOnExit(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "deleteOnExit", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testList() throws IOException {
        list(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "list", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testList2() throws IOException {
        list2(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "list", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testListFiles() throws IOException {
        listFiles(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "listFiles", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testListFiles2() throws IOException {
        listFiles2(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "listFiles", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testListFiles3() throws IOException {
        listFiles3(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "listFiles", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testMkdir() throws IOException {
        mkdir(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "mkdir", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testMkdirs() throws IOException {
        mkdirs(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "mkdirs", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testRenameTo() throws IOException {
        renameTo(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "renameTo", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testSetReadOnly() throws IOException {
        setReadOnly(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "setReadOnly", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testSetWritable() throws IOException {
        setWritable(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "setWritable", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testSetWritable2() throws IOException {
        setWritable2(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "setWritable", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testSetReadable() throws IOException {
        setReadable(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "setReadable", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testSetReadable2() throws IOException {
        setReadable2(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "setReadable", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testSetExecutable() throws IOException {
        setExecutable(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "setExecutable", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Test
    public void testSetExecutable2() throws IOException {
        setExecutable2(FILE_NAME);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation targetOperation = (FileOperation) operations.get(0);

        Assert.assertEquals("Invalid method Name", "setExecutable", targetOperation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", FILE_NAME, targetOperation.getFileName().get(0));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, targetOperation.getCaseType());
    }

    @Trace(dispatcher = true)
    private void exists(String filePath) throws IOException {
        new File(filePath).exists();
    }

    @Trace(dispatcher = true)
    private void createNewFile(String filePath) throws IOException {
        new File(filePath).createNewFile();
    }

    @Trace(dispatcher = true)
    private void delete(String filePath) throws IOException {
        new File(filePath).delete();
    }

    @Trace(dispatcher = true)
    private void deleteOnExit(String filePath) throws IOException {
        new File(filePath).deleteOnExit();
    }

    @Trace(dispatcher = true)
    private void list(String filePath) throws IOException {
        new File(filePath).list();
    }

    @Trace(dispatcher = true)
    private void list2(String filePath) throws IOException {
        FilenameFilter filter = null;
        new File(filePath).list(filter);
    }

    @Trace(dispatcher = true)
    private void listFiles(String filePath) throws IOException {
        new File(filePath).listFiles();
    }

    @Trace(dispatcher = true)
    private void listFiles2(String filePath) throws IOException {
        FilenameFilter filter = null;
        new File(filePath).listFiles(filter);
    }

    @Trace(dispatcher = true)
    private void listFiles3(String filePath) throws IOException {
        FileFilter filter = null;
        new File(filePath).listFiles(filter);
    }

    @Trace(dispatcher = true)
    private void mkdir(String filePath) throws IOException {
        new File(filePath).mkdir();
    }

    @Trace(dispatcher = true)
    private void mkdirs(String filePath) throws IOException {
        new File(filePath).mkdirs();
    }

    @Trace(dispatcher = true)
    private void renameTo(String filePath) throws IOException {
        String destPath = "/tmp/test-" + UUID.randomUUID();
        new File(filePath).renameTo( new File(destPath));
    }

    @Trace(dispatcher = true)
    private void setReadOnly(String filePath) throws IOException {
        new File(filePath).setReadOnly();
    }

    @Trace(dispatcher = true)
    private void setWritable(String filePath) throws IOException {
        new File(filePath).setWritable(false, false);
    }

    @Trace(dispatcher = true)
    private void setWritable2(String filePath) throws IOException {
        new File(filePath).setWritable(false);
    }

    @Trace(dispatcher = true)
    private void setReadable(String filePath) throws IOException {
        new File(filePath).setReadable(false, false);
    }

    @Trace(dispatcher = true)
    private void setReadable2(String filePath) throws IOException {
        new File(filePath).setReadable(false);
    }

    @Trace(dispatcher = true)
    private void setExecutable(String filePath) throws IOException {
        new File(filePath).setExecutable(false, false);
    }

    @Trace(dispatcher = true)
    private void setExecutable2(String filePath) throws IOException {
        new File(filePath).setExecutable(false);
    }

    @AfterClass
    public static void tearDown() {
        new File(FILE_NAME).delete();
    }
}
