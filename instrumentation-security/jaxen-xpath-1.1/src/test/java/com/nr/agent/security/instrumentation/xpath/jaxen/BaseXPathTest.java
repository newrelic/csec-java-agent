package com.nr.agent.security.instrumentation.xpath.jaxen;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import org.jaxen.BaseXPath;
import org.jaxen.Context;
import org.jaxen.ContextSupport;
import org.jaxen.XPath;
import org.jaxen.dom.DOMXPath;
import org.jaxen.dom.DocumentNavigator;
import org.jaxen.dom4j.Dom4jXPath;
import org.jaxen.javabean.JavaBeanXPath;
import org.jaxen.jdom.JDOMXPath;
import org.jaxen.xom.XOMXPath;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.newrelic.agent.security.instrumentation.xpath.jaxen", "org.jaxen" })
@Category({ Java17IncompatibleTest.class})
public class BaseXPathTest {
    private final String EXPRESSION = "/Customers/Customer";
    private final String XML_DOC = "src/test/resources/Customer.xml";
    @Test
    public void testSelectNodes() throws Exception {
        Document xmlDocument = DocumentBuilderFactory
                                .newInstance()
                                .newDocumentBuilder()
                                .parse(XML_DOC);

        XPath path = new DOMXPath(EXPRESSION);
        path.selectNodes(xmlDocument);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "selectNodes", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testSelectSingleNode() throws Exception {
        Document xmlDocument = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(XML_DOC);

        XPath path = new DOMXPath(EXPRESSION);
        path.selectSingleNode(xmlDocument);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "selectNodes", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testSelectNodes1() throws Exception {
        Document xmlDocument = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(XML_DOC);

        XPath path = new BaseXPath(EXPRESSION, new DocumentNavigator());
        path.selectNodes(xmlDocument);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "selectNodes", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testSelectNodes2() throws Exception {
        Document xmlDocument = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(XML_DOC);

        XPath path = new Dom4jXPath(EXPRESSION);
        path.selectNodes(xmlDocument);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "selectNodes", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testSelectNodes3() throws Exception {
        Document xmlDocument = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(XML_DOC);

        XPath path = new JavaBeanXPath(EXPRESSION);
        path.selectNodes(xmlDocument);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "selectNodes", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testSelectNodes4() throws Exception {

        XPath path = new JDOMXPath(EXPRESSION);
        Context context = new Context(new ContextSupport());
        path.selectNodes(context);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "selectNodes", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

    @Test
    public void testSelectNodes5() throws Exception {

        XPath path = new XOMXPath(EXPRESSION);
        Context context = new Context(new ContextSupport());
        path.selectNodes(context);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "selectNodes", operation.getMethodName());
        Assert.assertEquals("Invalid expression", EXPRESSION, operation.getExpression());
    }

}
