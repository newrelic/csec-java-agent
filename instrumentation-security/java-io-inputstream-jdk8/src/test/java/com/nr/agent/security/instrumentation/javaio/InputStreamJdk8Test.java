package com.nr.agent.security.instrumentation.javaio;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
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

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"java.io","com.newrelic.agent.security.instrumentation.javaio"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({Java17IncompatibleTest.class})
public class InputStreamJdk8Test {
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
            int i=inputStream.read();
            while (i!=-1) {
                i = inputStream.read();
            }
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
    public void testReadWithFiles2() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];
        try {
            InputStream inputStream = Files.newInputStream(Paths.get(FILE));
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
    @Ignore("This type of construct's instrumentation is in servlet module")
    public void testReadWithFileInputStream() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            InputStream inputStream = new FileInputStream(FILE);
            System.out.println(inputStream.hashCode());
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            int i=inputStream.read();
            while (i!=-1) {
                i = inputStream.read();
            }
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
    @Ignore("This type of construct's instrumentation is in servlet module")
    public void testReadWithByteArrayInputStream() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] expected = new byte[DATA.length()];

        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(DATA.getBytes());
            introspector.setRequestInputStreamHash(inputStream.hashCode());
            int i=inputStream.read();
            while (i!=-1) {
                i = inputStream.read();
            }
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
    public void testReadWithByteArrayInputStream1() throws JsonProcessingException {
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
}
