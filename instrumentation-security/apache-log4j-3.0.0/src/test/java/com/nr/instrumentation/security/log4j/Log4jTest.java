package com.nr.instrumentation.security.log4j;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.helper.Log4JStrSubstitutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.lookup.StrSubstitutor;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = "org.apache.logging.log4j.core", configName = "application_logging_context_data_enabled.yml")
public class Log4jTest {
    private final Logger logger = LogManager.getLogger(Log4jTest.class);
    private static final Map<String, String> MAP = new HashMap<>();
    private final String SOURCE = " ${Key} ";
    private final Log4JStrSubstitutor EXPECTED = new Log4JStrSubstitutor("Key", new StringBuilder(" value "), 1, 7);

    @BeforeClass
    public static void setLogLevel() {
        MAP.put("Key", "value");
    }

    @Test
    public void testResolveVariable() {
        Properties info = new Properties();
        info.setProperty("Key", "value");
        String str = StrSubstitutor.replace(SOURCE, info);
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable1() {
        String str = StrSubstitutor.replace(SOURCE, MAP);
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable2() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        String str = substitutor.replace(SOURCE);
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actaul = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actaul);
    }

    @Test
    public void testResolveVariable3() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        String str = substitutor.replace(SOURCE, 0, SOURCE.length());
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable4() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        String str = substitutor.replace(SOURCE.toCharArray());
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable5() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        String str = substitutor.replace(SOURCE.toCharArray(), 0, SOURCE.length());
        logger.error(str);


        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable6() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        String str = substitutor.replace(new StringBuffer(SOURCE));
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable7() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        String str = substitutor.replace(new StringBuffer(SOURCE), 0, SOURCE.length());
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable8() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        String str = substitutor.replace(new StringBuilder(SOURCE));
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable9() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        String str = substitutor.replace(new StringBuilder(SOURCE), 0, SOURCE.length());
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable10() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        boolean str = substitutor.replaceIn(new StringBuilder(SOURCE));
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }

    @Test
    public void testResolveVariable11() {
        StrSubstitutor substitutor = new StrSubstitutor(MAP);
        boolean str = substitutor.replaceIn(new StringBuilder(SOURCE), 1, SOURCE.length()-1);
        logger.error(str);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Log4JStrSubstitutor actual = introspector.getLog4JStrSubstitutor();
        assertLog4JStrSubstitutor(EXPECTED, actual);
    }


    private void assertLog4JStrSubstitutor(Log4JStrSubstitutor expected, Log4JStrSubstitutor actual) {
        Assert.assertEquals("Invalid variable name", expected.getVariableName(), actual.getVariableName());
        Assert.assertEquals("Invalid buffer value", expected.getBuf().toString(), actual.getBuf().toString());
        Assert.assertEquals("Wrong Start position of variable", expected.getStartPos(), actual.getStartPos());
        Assert.assertEquals("Wrong end position of variable", expected.getEndPos(), actual.getEndPos());
    }
}