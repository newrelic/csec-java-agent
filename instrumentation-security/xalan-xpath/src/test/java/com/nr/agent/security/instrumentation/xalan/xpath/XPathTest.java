package com.nr.agent.security.instrumentation.xalan.xpath;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import org.apache.xml.utils.PrefixResolver;
import org.apache.xml.utils.PrefixResolverDefault;
import org.apache.xml.utils.SAXSourceLocator;
import org.apache.xpath.XPath;
import org.apache.xpath.XPathContext;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.SourceLocator;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = "org.apache.xpath")
public class XPathTest {
    private final String XML_DOC = "src/test/resources/Customer.xml";
    private final String EXPRESSION = "/Customers/Customer";
    @Test
    public void testExecute() throws TransformerException, IOException, ParserConfigurationException, SAXException {

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
    public void testExecute1() throws TransformerException, IOException, ParserConfigurationException, SAXException {

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
}
