package com.nr.instrumentation.security.xalan.xpath;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import com.sun.org.apache.xml.internal.utils.DefaultErrorHandler;
import com.sun.org.apache.xml.internal.utils.PrefixResolver;
import com.sun.org.apache.xml.internal.utils.PrefixResolverDefault;
import com.sun.org.apache.xml.internal.utils.SAXSourceLocator;
import com.sun.org.apache.xpath.internal.Expression;
import com.sun.org.apache.xpath.internal.XPath;
import com.sun.org.apache.xpath.internal.XPathContext;
import com.sun.org.apache.xpath.internal.compiler.Compiler;
import com.sun.org.apache.xpath.internal.compiler.FunctionTable;
import com.sun.org.apache.xpath.internal.compiler.XPathParser;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.ErrorListener;
import javax.xml.transform.SourceLocator;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = { "com.sun.org.apache.xpath.internal" })
public class XPathInternalTest {
    private final String XML_DOC = "src/test/resources/Customer.xml";
    private final String EXPRESSION = "/Customers/Customer";

    @Test
    public void testExecute() throws Exception {

        Document document = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(XML_DOC);
        Node contextNode = document.getDocumentElement();

        SourceLocator sourceLocator = new SAXSourceLocator();
        PrefixResolver NamespaceContext = new PrefixResolverDefault(contextNode);
        XPath xPath = new XPath(EXPRESSION, sourceLocator, NamespaceContext, 1, null);
        XPathContext xctxt = new XPathContext();

        xPath.execute(xctxt, 1, NamespaceContext);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("Invalid expression", "/Customers/Customer", operation.getExpression());
    }

    @Test
    public void testExecute1() throws Exception {

        Document document = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(XML_DOC);
        Node contextNode = document.getDocumentElement();

        SourceLocator sourceLocator = new SAXSourceLocator();
        PrefixResolver NamespaceContext = new PrefixResolverDefault(contextNode);
        XPath xPath = new XPath(EXPRESSION, sourceLocator, NamespaceContext, 1, null);
        XPathContext xctxt = new XPathContext();

        xPath.execute(xctxt, contextNode, NamespaceContext);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("Invalid expression", "/Customers/Customer", operation.getExpression());
    }

    @Test
    public void testExecute2() throws Exception {

        Document document = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(XML_DOC);
        Node contextNode = document.getDocumentElement();

        SourceLocator sourceLocator = new SAXSourceLocator();
        PrefixResolver NamespaceContext = new PrefixResolverDefault(contextNode);
        XPath xPath = new XPath(EXPRESSION, sourceLocator, NamespaceContext, 1);

        XPathContext xctxt = new XPathContext();
        xPath.execute(xctxt, contextNode, NamespaceContext);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("Invalid expression", "/Customers/Customer", operation.getExpression());
    }

    @Test
    public void testExecute3() throws TransformerException, IOException, ParserConfigurationException, SAXException {

        Document document = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(XML_DOC);
        Node contextNode = document.getDocumentElement();

        SourceLocator sourceLocator = new SAXSourceLocator();
        PrefixResolver NamespaceContext = new PrefixResolverDefault(contextNode);

        new XPath(EXPRESSION, sourceLocator, NamespaceContext, 1, new DefaultErrorHandler(), new FunctionTable())
                .execute(new XPathContext(), contextNode, NamespaceContext);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("Invalid expression", "/Customers/Customer", operation.getExpression());
    }

    @Test
    @Ignore("no operation is generating as PatternString is null in instrumentation")
    public void testExecute4() throws TransformerException, IOException, ParserConfigurationException, SAXException {
        Document document = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(XML_DOC);
        Node contextNode = document.getDocumentElement();

        SourceLocator sourceLocator = new SAXSourceLocator();
        PrefixResolver NamespaceContext = new PrefixResolverDefault(contextNode);
        ErrorListener errorListener = new DefaultErrorHandler();
        FunctionTable table = new FunctionTable();

        XPathParser parser = new XPathParser(errorListener, sourceLocator);
        Compiler compiler = new Compiler(errorListener, sourceLocator, table);

        parser.initXPath(compiler, EXPRESSION, NamespaceContext);
        Expression expr = compiler.compileExpression(2);

        new XPath(expr).execute(new XPathContext(), contextNode, NamespaceContext);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("Invalid expression", "/Customers/Customer", operation.getExpression());
    }
}
