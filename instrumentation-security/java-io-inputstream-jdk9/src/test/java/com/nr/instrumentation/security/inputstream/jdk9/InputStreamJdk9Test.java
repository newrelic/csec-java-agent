package com.nr.instrumentation.security.inputstream.jdk9;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.security.test.marker.Java11IncompatibleTest;
import com.newrelic.security.test.marker.Java8IncompatibleTest;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Category({ Java8IncompatibleTest.class, Java11IncompatibleTest.class })
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"nr.java.io","com.nr.instrumentation.security.javaio"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class InputStreamJdk9Test {
    private static String FILE;
    private static String FILE_TEMP;
    private static String DIR;
    private static String DATA;
    private static List<String> stuffToClean = new ArrayList<>();

    @BeforeClass
    public static void retransformRequiredClasses() {
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
        String uuid = String.valueOf(UUID.randomUUID());
        DIR = "/tmp/csec-"+ uuid;
        FILE = "/tmp/test-" + uuid;
        FILE_TEMP = FILE+".tmp";
        stuffToClean.add(FILE);
        stuffToClean.add(FILE_TEMP);
        stuffToClean.add(DIR);
        File tempFile = new File(FILE);
        tempFile.createNewFile();
        DATA = "This is written - " + uuid;
        BufferedWriter writer = new BufferedWriter(new FileWriter(FILE));
        writer.write(DATA);

        writer.close();

        System.out.println("Wrote " + tempFile.getAbsolutePath());
    }

    @Test
    public void testReadWithFiles() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            InputStream inputStream = Files.newInputStream(Paths.get(FILE));
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            while (inputStream.read()!=-1);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(DATA, meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadWithFiles1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = Files.newInputStream(Paths.get(FILE));
            System.out.println("in test now : "+inputStream.hashCode());
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            System.out.println("result: "+inputStream.read(expected));
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected), meta.getRequest().getBody().toString());
    }

    @Test
    @Ignore
    // FIXME: not working, need to check the issue
    public void testReadWithFiles2() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = Files.newInputStream(Paths.get(FILE));
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            System.out.println(inputStream.read(expected, 5, 25));
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected).substring(5, 30), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadAllBytesWithFiles() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = Files.newInputStream(Paths.get(FILE));
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            expected = inputStream.readAllBytes();
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadNBytesWithFiles() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = Files.newInputStream(Paths.get(FILE));
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            expected = inputStream.readNBytes(30);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected).substring(0, 30), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadNBytesWithFiles1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = Files.newInputStream(Paths.get(FILE));
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            inputStream.readNBytes(expected, 5, 25);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected).substring(5, 30), meta.getRequest().getBody().toString());
    }

    @Test
    @Ignore("This type of construct's instrumentation is in servlet module")
    public void testReadWithFileInputStream() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            InputStream inputStream = new FileInputStream(FILE);
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            while (inputStream.read()!=-1);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(DATA, meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadWithFileInputStream1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = new FileInputStream(FILE);
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            inputStream.read(expected);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadWithFileInputStream2() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = new FileInputStream(FILE);
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            inputStream.read(expected, 5, 25);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected).substring(5, 30), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadAllBytesWithFileInputStream() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = new FileInputStream(FILE);
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            expected = inputStream.readAllBytes();
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadNBytesWithFileInputStream() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = new FileInputStream(FILE);
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            expected = inputStream.readNBytes(30);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected).substring(0, 30), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadNBytesWithFileInputStream1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = new FileInputStream(FILE);
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            inputStream.readNBytes(expected, 5, 25);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected).substring(5, 30), meta.getRequest().getBody().toString());
    }

    @Test
    @Ignore("This type of construct's instrumentation is in servlet module")
    public void testReadWithByteArrayInputStream() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];

        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(DATA.getBytes());
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            while (inputStream.read()!=-1);
            inputStream.close();
        } catch(Exception e) {
            e.getStackTrace();
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadWithByteArrayInputStream1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(DATA.getBytes());
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            inputStream.read(expected);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadWithByteArrayInputStream2() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(DATA.getBytes());
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            inputStream.read(expected, 5, 25);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected).substring(5, 30), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadAllBytesWithByteArrayInputStream() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(DATA.getBytes());
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            expected = inputStream.readAllBytes();
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadNBytesWithByteArrayInputStream() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(DATA.getBytes());
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            expected = inputStream.readNBytes(30);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected).substring(0, 30), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadNBytesWithByteArrayInputStream1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(DATA.getBytes());
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            inputStream.readNBytes(expected, 5, 25);
            inputStream.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(expected).substring(5, 30), meta.getRequest().getBody().toString());
    }
}
