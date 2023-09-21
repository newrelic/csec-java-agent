package com.newrelic.agent.security.instrumentation.saxpath;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import com.newrelic.agent.security.instrumentation.saxpath.XPATHUtils;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.saxpath.XPathReader;
import org.saxpath.conformance.ConformanceXPathHandler;
import org.saxpath.helpers.XPathReaderFactory;

import java.util.List;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.saxpath"})
public class XPathTest {
    private final String EXPRESSION = "/Customers/Customer";

    @Test
    public void testParse() throws Exception {

        XPathReader reader = XPathReaderFactory.createReader();
        System.out.println(reader.getXPathHandler());
        reader.parse(EXPRESSION);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_PARSE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", "/Customers/Customer", operation.getExpression());
    }

    @Test
    public void testParse1() throws Exception {

        XPathReader reader = XPathReaderFactory.createReader();
        ConformanceXPathHandler handler = new ConformanceXPathHandler();
        reader.setXPathHandler(handler);
        reader.parse(EXPRESSION);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_PARSE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", "/Customers/Customer", operation.getExpression());
    }
}
