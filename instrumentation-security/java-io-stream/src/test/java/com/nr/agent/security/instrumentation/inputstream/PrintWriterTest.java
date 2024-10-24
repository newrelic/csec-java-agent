package com.nr.agent.security.instrumentation.inputstream;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "java.io", "com.newrelic.agent.security.instrumentation.inputstream"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PrintWriterTest {
    private static String FILE;
    private static String FILE_TEMP;
    private static String DIR;
    private static String DATA;
    private static List<String> stuffToClean = new ArrayList<>();

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
    public void testAppendChar() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.append(DATA.charAt(5));
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(String.valueOf(DATA.charAt(5)), meta.getResponse().getBody().toString());
    }

    @Test
    public void testAppendString() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.append(DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testAppendString1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.append(DATA, 2, 20);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA.substring(2, 20), meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintBoolean() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.print(true);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("true", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintChar() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.print(DATA.charAt(9));
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(String.valueOf(DATA.charAt(9)), meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintCharArray() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        char[] input = DATA.toCharArray();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.print(input);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintInt() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.print(2);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("2", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintLong() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.print(2L);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("2", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintFloat() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.print(2.0f);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("2.0", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintDouble() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.print(2.0);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("2.0", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintString() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.print(DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintObject() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Object ob = new Object();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.print(ob);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(ob.toString(), meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintln() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println();
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintlnBoolean() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println(true);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("true\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintlnChar() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println(DATA.charAt(9));
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(String.valueOf(DATA.charAt(9))+"\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintlnCharArray() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        char[] input = DATA.toCharArray();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println(input);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA+"\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintlnInt() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println(2);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("2\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintlnLong() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println(2L);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("2\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintlnFloat() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println(2.0f);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("2.0\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintlnDouble() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println(2.0);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("2.0\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintlnString() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println(DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA+"\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintlnObject() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Object ob = new Object();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.println(ob);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(ob+"\n", meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintf() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.printf("test %s", DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("test "+DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintf1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.printf(DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintfLocale() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.printf(Locale.ENGLISH, "test %s", DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("test "+DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testPrintfLocale1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.printf(Locale.ENGLISH, DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testWriteString() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.write(DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testWriteString1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.write(DATA, 2, 8);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA.substring(2, 8), meta.getResponse().getBody().toString());
    }

    @Test
    public void testWriteChar() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        char[] input = DATA.toCharArray();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.write(input);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testWriteChar1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        char[] input = DATA.toCharArray();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.write(input, 2, 8);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA.substring(2, 10), meta.getResponse().getBody().toString());
    }

    @Test
    public void testWriteInt() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.write(1);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(1, Integer.parseInt(meta.getResponse().getBody().toString()));
    }

    @Test
    public void testFormat() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.format("test %s", DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("test "+DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testFormat1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.format(DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testFormatLocale() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.format(Locale.ENGLISH, "test %s", DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals("test "+DATA, meta.getResponse().getBody().toString());
    }

    @Test
    public void testFormatLocale1() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        try {
            PrintWriter writer = new PrintWriter(System.out);
            introspector.setResponseWriterHash(writer.hashCode());
            writer.format(Locale.ENGLISH, DATA);
            writer.flush();
            writer.close();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        SecurityMetaData meta = introspector.getSecurityMetaData();
        Assert.assertNotNull("Empty security meta data", meta);
        Assert.assertEquals(DATA, meta.getResponse().getBody().toString());
    }

}
