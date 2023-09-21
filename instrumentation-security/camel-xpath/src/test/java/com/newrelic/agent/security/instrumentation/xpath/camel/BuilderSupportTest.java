package com.newrelic.agent.security.instrumentation.xpath.camel;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import org.apache.camel.CamelContext;
import org.apache.camel.builder.BuilderSupport;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.builder.Namespaces;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = { "org.apache.camel.builder" })

public class BuilderSupportTest {
    private final String EXPRESSION = "/Customers/Customer";
    @Test
    public void testXPath() {
        Namespaces ns1 = new Namespaces();
        CamelContext context = new DefaultCamelContext();
        BuilderSupport BS = new BuilderSupport(context) {};
        BS.xpath(EXPRESSION, String.class, ns1);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "xpath", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testXPath1() {
        CamelContext context = new DefaultCamelContext();
        BuilderSupport BS = new BuilderSupport(context) {};
        BS.xpath(EXPRESSION);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "xpath", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testXPath2() {
        CamelContext context = new DefaultCamelContext();
        BuilderSupport BS = new BuilderSupport(context) {};
        BS.xpath(EXPRESSION, String.class);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "xpath", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testXPath3() {
        Namespaces ns1 = new Namespaces();
        CamelContext context = new DefaultCamelContext();
        BuilderSupport BS = new BuilderSupport(context) {};
        BS.xpath(EXPRESSION, ns1);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "xpath", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }
}
