package com.nr.agent.security.instrumentation.inputstream;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "java.io", "com.newrelic.agent.security.instrumentation.inputstream"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BufferedReaderTest {
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
    public void testRead(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            FileReader fr = new FileReader(FILE);
            BufferedReader br = new BufferedReader(fr);
            introspector.setRequestReaderHash(br.hashCode());
            int data = br.read();
            while (data != -1) {
                System.out.print((char) data);
                data = br.read();
            }
            br.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(DATA, meta.getRequest().getBody().toString());
    }

    @Test
    public void testRead1(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        char[] input = new char[DATA.length()];
        try {
            FileReader fr = new FileReader(FILE);
            BufferedReader br = new BufferedReader(fr);
            introspector.setRequestReaderHash(br.hashCode());
            br.read(input);
            br.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(input), meta.getRequest().getBody().toString());
    }

    @Test
    public void testRead2(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        char[] input = new char[30];
        try {
            FileReader fr = new FileReader(FILE);
            BufferedReader br = new BufferedReader(fr);
            introspector.setRequestReaderHash(br.hashCode());
            br.read(input, 3, 27);
            br.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(new String(input).substring(3, 30), meta.getRequest().getBody().toString());
    }

    @Test
    public void testReadLine(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            FileReader fr = new FileReader(FILE);
            BufferedReader br = new BufferedReader(fr);
            introspector.setRequestReaderHash(br.hashCode());
            String data = br.readLine();
            System.out.println(data);
            br.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertFalse("Empty request in security meta data", meta.getRequest().isEmpty());
        Assert.assertEquals(DATA, meta.getRequest().getBody().toString());
    }

    @Test
    public void testErrorInRead(){
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        char[] input = DATA.toCharArray();
        try {
            FileReader fr = new FileReader(FILE);
            BufferedReader br = new BufferedReader(fr);
            introspector.setRequestReaderHash(br.hashCode());
            int data = br.read(input, 2, 100);
            System.out.println(data);
            br.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("", meta.getRequest().getBody().toString());
    }
}
