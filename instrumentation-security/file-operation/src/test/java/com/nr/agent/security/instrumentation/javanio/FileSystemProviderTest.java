package com.nr.agent.security.instrumentation.javanio;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.instrument.UnmodifiableClassException;
import java.net.URISyntaxException;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.ByteChannel;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"java.io", "java.nio"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FileSystemProviderTest {

    private static String FILE;
    private static String FILE_TEMP;
    private static String DIR;

    private static List<String> stuffToClean = new ArrayList<>();

    @BeforeClass
    public static void retransformRequiredClasses() throws UnmodifiableClassException {
        TestSetupBringUp.bringUp();
    }

    @AfterClass
    public static void cleanUp(){
        for (String s : stuffToClean) {
            File f= new File(s);
            f.delete();
        }
    }

    @Before
    public void createTempFile() throws IOException {
        DIR = "/tmp/csec-"+UUID.randomUUID();
        FILE = "/tmp/test-" + UUID.randomUUID();
        FILE_TEMP = FILE+".tmp";
        stuffToClean.add(FILE);
        stuffToClean.add(FILE_TEMP);
        stuffToClean.add(DIR);
        File tempFile = new File(FILE);
        tempFile.createNewFile();
        System.out.println("Wrote " + tempFile.getAbsolutePath());
    }

    @Test
    public void testCopy() throws IOException, URISyntaxException {
        callCopy();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        fileNames.add(FILE_TEMP);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "copy", operation.getMethodName());
    }

    @Test
    public void testNewInputStream() throws IOException, URISyntaxException {
        callNewInputStream();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "newInputStream", operation.getMethodName());
    }

    @Test
    public void testNewOutputStream() throws IOException, URISyntaxException, InterruptedException {
        callNewOutputStream();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "newOutputStream", operation.getMethodName());
    }

    @Test
    public void testNewFileChannel() throws IOException, URISyntaxException, InterruptedException {
        callNewFileChannel();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "newFileChannel", operation.getMethodName());
    }

    @Test
    public void testNewAsynchronousFileChannel() throws IOException, URISyntaxException, InterruptedException {
        callNewAsynchronousFileChannel();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "newAsynchronousFileChannel", operation.getMethodName());
    }

    @Test
    public void testNewByteFileChannel() throws IOException, URISyntaxException, InterruptedException {
        callNewByteFileChannel();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "newByteChannel", operation.getMethodName());
    }

    @Test
    public void testCreateDirectory() throws IOException, URISyntaxException, InterruptedException {
        callCreateDirectory();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (DIR.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(DIR);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "createDirectory", operation.getMethodName());
    }

    @Test
    public void testMove() throws IOException, URISyntaxException {
        callMove();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        fileNames.add(FILE_TEMP);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "move", operation.getMethodName());
    }

    @Test
    public void testCreateSymbolicLink() throws IOException, URISyntaxException {
        callCreateSymbolicLink();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE_TEMP.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        fileNames.add(FILE_TEMP);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "createSymbolicLink", operation.getMethodName());
    }

    @Test
    public void testCreateLink() throws IOException, URISyntaxException {
        callCreateLink();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE_TEMP.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        fileNames.add(FILE_TEMP);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "createLink", operation.getMethodName());
    }

    @Test
    public void testDelete() throws IOException, URISyntaxException {
        callDelete();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "delete", operation.getMethodName());
    }

    @Test
    public void testDeleteIfExists() throws IOException, URISyntaxException {
        callDeleteIfExists();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "deleteIfExists", operation.getMethodName());
    }

    @Test
    public void testSetAttribute() throws IOException {
        callSetAttribute();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (FILE.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(FILE);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "setAttribute", operation.getMethodName());
    }

    @Test
    public void testNewDirectoryStream() throws IOException {
        callNewDirectoryStream();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        FileOperation operation = null;
        for (AbstractOperation op : operations) {
            if (DIR.equals(((FileOperation) op).getFileName().get(0))) {
                operation = (FileOperation) op;
            }
        }
        Assert.assertNotNull("No target operation found.", operation);
        ArrayList<String> fileNames = new ArrayList<String>();
        fileNames.add(DIR);
        Assert.assertTrue("Invalid executed parameters.", operation.getFileName().containsAll(fileNames));
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.FILE_OPERATION, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "newDirectoryStream", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    private void callCopy() throws IOException {
        Files.copy(Paths.get(FILE), Paths.get(FILE_TEMP));

//        FileSystem fileSys = FileSystems.getDefault();
//        FileSystemProvider provider = fileSys.provider();
//        provider.copy(fileSys.getPath(FILE), fileSys.getPath(FILE_TEMP), StandardCopyOption.REPLACE_EXISTING);
    }

    @Trace(dispatcher = true)
    private void callNewInputStream() throws URISyntaxException, IOException {
        FileSystem fileSys = FileSystems.getDefault();
        FileSystemProvider provider = fileSys.provider();
        InputStream in = provider.newInputStream(fileSys.getPath(FILE), StandardOpenOption.READ);
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        String line;
        StringBuilder sb = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            sb.append(line + System.lineSeparator());
        }
    }

    @Trace(dispatcher = true)
    private void callNewOutputStream() throws URISyntaxException, IOException, InterruptedException {
        FileSystem fileSys = FileSystems.getDefault();
        FileSystemProvider provider = fileSys.provider();
        OutputStream out = provider.newOutputStream(fileSys.getPath(FILE), StandardOpenOption.WRITE);
        out.write("New dummy data".getBytes());
    }

    @Trace(dispatcher = true)
    private void callNewFileChannel() throws IOException {
        FileChannel fileChannel = null;
        try {
            FileSystem fileSys = FileSystems.getDefault();
            FileSystemProvider provider = fileSys.provider();

            HashSet<OpenOption> readOptions = new HashSet<OpenOption>();
            readOptions.add(StandardOpenOption.READ);
            readOptions.add(StandardOpenOption.SYNC);

            HashSet<PosixFilePermission> perm = new HashSet<>();
            perm.add(PosixFilePermission.OWNER_READ);
            FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perm);

            fileChannel = provider.newFileChannel(fileSys.getPath(FILE), readOptions, attr);
            System.out.println("FileChannel size = " + fileChannel.size());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        finally {
            fileChannel.close();
        }
    }

    @Trace(dispatcher = true)
    private void callNewAsynchronousFileChannel() throws IOException {
        AsynchronousFileChannel fileChannel = null;
        try {
            ExecutorService executor = Executors.newFixedThreadPool(1);

            FileSystem fileSys = FileSystems.getDefault();
            FileSystemProvider provider = fileSys.provider();

            HashSet<OpenOption> readOptions = new HashSet<OpenOption>();
            readOptions.add(StandardOpenOption.READ);
            readOptions.add(StandardOpenOption.SYNC);

            HashSet<PosixFilePermission> perm = new HashSet<>();
            perm.add(PosixFilePermission.OWNER_READ);
            FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perm);

            fileChannel = provider.newAsynchronousFileChannel(fileSys.getPath(FILE), readOptions, executor, attr);
            System.out.println("AsynchronousFileChannel size = " + fileChannel.size());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        finally {
            fileChannel.close();
        }
    }

    @Trace(dispatcher = true)
    private void callNewByteFileChannel() throws IOException {
        ByteChannel fileChannel = null;
        try {
            FileSystem fileSys = FileSystems.getDefault();
            FileSystemProvider provider = fileSys.provider();

            HashSet<OpenOption> readOptions = new HashSet<OpenOption>();
            readOptions.add(StandardOpenOption.READ);
            readOptions.add(StandardOpenOption.SYNC);

            HashSet<PosixFilePermission> perm = new HashSet<>();
            perm.add(PosixFilePermission.OWNER_READ);
            FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perm);

            fileChannel = provider.newByteChannel(fileSys.getPath(FILE), readOptions, attr);
            System.out.println("ByteChannel size = " + fileChannel.isOpen());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        finally {
            fileChannel.close();
        }
    }

    @Trace(dispatcher = true)
    private void callCreateDirectory() throws URISyntaxException, IOException, InterruptedException {
        FileSystem fileSys = FileSystems.getDefault();
        FileSystemProvider provider = fileSys.provider();

        HashSet<PosixFilePermission> perm = new HashSet<>();
        perm.add(PosixFilePermission.OWNER_WRITE);
        perm.add(PosixFilePermission.OWNER_EXECUTE);
        perm.add(PosixFilePermission.OWNER_READ);
        FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perm);

        provider.createDirectory(Paths.get(DIR), attr);
    }

    @Trace(dispatcher = true)
    private void callMove() throws IOException {
        Files.move(Paths.get(FILE), Paths.get(FILE_TEMP));

//        FileSystem fileSys = FileSystems.getDefault();
//        FileSystemProvider provider = fileSys.provider();
//        provider.move(fileSys.getPath(FILE), fileSys.getPath(FILE_TEMP), StandardCopyOption.REPLACE_EXISTING);
    }

    @Trace(dispatcher = true)
    private void callCreateSymbolicLink() throws IOException {
        Files.createSymbolicLink(Paths.get(FILE_TEMP), Paths.get(FILE));

//        FileSystem fileSys = FileSystems.getDefault();
//        FileSystemProvider provider = fileSys.provider();
//        provider.createSymbolicLink(Paths.get(FILE_TEMP), Paths.get(FILE));
    }

    @Trace(dispatcher = true)
    private void callCreateLink() throws IOException {
        Files.createLink(Paths.get(FILE_TEMP), Paths.get(FILE));

//        FileSystem fileSys = FileSystems.getDefault();
//        FileSystemProvider provider = fileSys.provider();
//        provider.createLink(Paths.get(FILE_TEMP), Paths.get(FILE));
    }

    @Trace(dispatcher = true)
    private void callDelete() throws IOException {
        Files.delete(Paths.get(FILE));

//        FileSystem fileSys = FileSystems.getDefault();
//        FileSystemProvider provider = fileSys.provider();
//        provider.delete(Paths.get(FILE));
    }

    @Trace(dispatcher = true)
    private void callDeleteIfExists() throws IOException {
        Files.deleteIfExists(Paths.get(FILE));

//        FileSystem fileSys = FileSystems.getDefault();
//        FileSystemProvider provider = fileSys.provider();
//        provider.deleteIfExists(Paths.get(FILE));
    }

    @Trace(dispatcher = true)
    private void callSetAttribute() throws IOException {
        Files.setAttribute(Paths.get(FILE),"basic:lastModifiedTime", FileTime.fromMillis(10000));

//        FileSystem fileSys = FileSystems.getDefault();
//        FileSystemProvider provider = fileSys.provider();
//        provider.setAttribute(Paths.get(FILE),"basic:lastModifiedTime", FileTime.fromMillis(10000));
    }

    @Trace(dispatcher = true)
    private void callNewDirectoryStream() throws IOException {
        FileSystem fileSys = FileSystems.getDefault();
        FileSystemProvider provider = fileSys.provider();

        new File(DIR).mkdirs();
        Path dir = Paths.get(DIR);
        final FileSystem fs = dir.getFileSystem();
        final PathMatcher matcher = fs.getPathMatcher("glob:lastModifiedTime");
        final DirectoryStream.Filter<Path> filter = new DirectoryStream.Filter<Path>()
        {
            @Override
            public boolean accept (Path entry)
            {
                return matcher.matches(entry.getFileName());
            }
        };

        provider.newDirectoryStream(dir, filter);
    }
}
