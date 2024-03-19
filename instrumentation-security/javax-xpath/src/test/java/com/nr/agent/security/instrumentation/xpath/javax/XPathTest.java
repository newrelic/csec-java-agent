package com.nr.agent.security.instrumentation.xpath.javax;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import com.newrelic.agent.security.instrumentation.xpath.javax.XPATHUtils;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.util.List;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.xml.xpath", "com.sun.org.apache.xpath.internal" })
@Category({ Java17IncompatibleTest.class})
public class XPathTest {

    private final String XML_DOC = "src/test/resources/Customer.xml";
    private final String EXPRESSION = "/Customers/Customer";

    @Test
    public void testEvaluate() throws Exception {
        InputSource source = new InputSource(XML_DOC);
        XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.evaluate(EXPRESSION, source);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_EVALUATE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testEvaluate1() throws Exception {
        InputSource source = new InputSource(XML_DOC);
        XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.evaluate(EXPRESSION, source, XPathConstants.STRING);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_EVALUATE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testEvaluate2() throws Exception {
        Document xmlDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(XML_DOC);
        XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.evaluate(EXPRESSION, xmlDocument);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_EVALUATE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testEvaluate3() throws Exception {
        Document xmlDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(XML_DOC);
        XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.evaluate(EXPRESSION, xmlDocument, XPathConstants.STRING);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_EVALUATE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }
    @Test
    @Ignore("This type of construct's instrumentation is in xalan-xpath module")
    public void testCompile() throws Exception {
        Document xmlDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(XML_DOC);
        XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.compile(EXPRESSION).evaluate(xmlDocument, XPathConstants.STRING);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_EVALUATE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    @Ignore("This type of construct's instrumentation is in xalan-xpath module")
    public void testCompile1() throws Exception {
        Document xmlDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(XML_DOC);
        XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.compile(EXPRESSION).evaluate(xmlDocument);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_EVALUATE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    @Ignore("This type of construct's instrumentation is in xalan-xpath module")
    public void testCompile2() throws Exception {
        InputSource source = new InputSource(XML_DOC);
        XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.compile(EXPRESSION).evaluate(source, XPathConstants.STRING);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_EVALUATE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    @Ignore("This type of construct's instrumentation is in xalan-xpath module")
    public void testCompile3() throws Exception {
        InputSource source = new InputSource(XML_DOC);
        XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.compile(EXPRESSION).evaluate(source);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", XPATHUtils.METHOD_EVALUATE, operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }
}
