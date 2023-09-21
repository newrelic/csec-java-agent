package com.newrelic.agent.security.instrumentation.inputstream;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "java.io", "com.newrelic.agent.security.instrumentation.inputstream"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ReaderTest {
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
    @Ignore("This type of construct's instrumentation is in BufferedReader class of this module")
    public void testReadWithFileReader(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            Reader reader = new FileReader(FILE);
            introspector.setRequestReaderHash(reader.hashCode());
            int data = reader.read();
            while (data != -1) {
                data = reader.read();
            }
            reader.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA.substring(2, 20), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadWithFileReader1(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        char[] input = new char[DATA.length()];
        try {
            Reader reader = new FileReader(FILE);
            introspector.setRequestReaderHash(reader.hashCode());
            int data = reader.read(input);
            reader.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(new String(input), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadWithFileReader2(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        CharBuffer input = CharBuffer.wrap(new char[DATA.length()]);
        try {
            Reader reader = new FileReader(FILE);
            introspector.setRequestReaderHash(reader.hashCode());
            int data = reader.read(input);
            System.out.println(data);
            reader.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(new String(input.array()), meta.getRequest().getBody().toString());
    }

    @Test
    @Ignore("This type of construct's instrumentation is in BufferedReader class of this module")
    public void testReadWithInputStreamReader(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            FileInputStream file = new FileInputStream(FILE);

            Reader reader = new InputStreamReader(file);
            introspector.setRequestReaderHash(reader.hashCode());
            int data = reader.read();
            while (data != -1) {
                data = reader.read();
            }

            reader.close();
            file.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadWithInputStreamReader1(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        char[] input = new char[DATA.length()];
        try {
            FileInputStream file = new FileInputStream(FILE);

            Reader reader = new InputStreamReader(file);
            introspector.setRequestReaderHash(reader.hashCode());
            int data = reader.read(input);

            reader.close();
            file.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(new String(input), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadWithInputStreamReader2(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        CharBuffer input = CharBuffer.wrap(new char[DATA.length()]);
        try {
            FileInputStream file = new FileInputStream(FILE);

            Reader reader = new InputStreamReader(file);
            introspector.setRequestReaderHash(reader.hashCode());
            int data = reader.read(input);

            reader.close();
            file.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(new String(input.array()), meta.getRequest().getBody().toString());
    }
}
