package com.nr.agent.security.instrumentation.inputstream;

import com.fasterxml.jackson.core.JsonProcessingException;
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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "java.io", "com.newrelic.agent.security.instrumentation.inputstream"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class OutputStreamTest {
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

        System.out.println("Wrote " + tempFile.getAbsolutePath());
    }

    @Test
    public void testWrite() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            byte[] bytes = DATA.getBytes();
            try (OutputStream out = new FileOutputStream(FILE)) {
                introspector.setResponseOutStreamHash(out.hashCode());
                out.write(bytes);
            }
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
//        Assert.assertFalse("Empty response in security meta data", meta.getResponse().isEmpty());
        Assert.assertEquals(DATA, meta.getResponse().getResponseBody().toString());
    }

    @Test
    public void testWrite1() throws JsonProcessingException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] bytes = DATA.getBytes();
        try {
            try (OutputStream out = new FileOutputStream(FILE)) {
                introspector.setResponseOutStreamHash(out.hashCode());
                out.write(bytes, 2, 25);
            }
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
//        Assert.assertFalse("Empty response in security meta data", meta.getResponse().isEmpty());
        Assert.assertEquals(DATA.substring(2, 27), meta.getResponse().getResponseBody().toString());
    }

    @Test
    public void testErrorInWrite() throws JsonProcessingException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        byte[] bytes = DATA.getBytes();
        try {
            try (OutputStream out = new FileOutputStream(FILE)) {
                introspector.setResponseOutStreamHash(out.hashCode());
                out.write(bytes, 2, 100);
            }
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertTrue("Non-empty response in security meta data", meta.getResponse().isEmpty());
        Assert.assertEquals("", meta.getResponse().getResponseBody().toString());
    }
}
