import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import org.apache.commons.jxpath.Container;
import org.apache.commons.jxpath.JXPathContext;
import org.apache.commons.jxpath.ri.compiler.Expression;
import org.apache.commons.jxpath.xml.DocumentContainer;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.URL;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.apache.commons.jxpath")
public class JXPathTest {

    @Test
    public void testGetValue() {
        URL url = JXPathTest.class.getResource("/students.xml");

        Container container = new DocumentContainer(url);

        JXPathContext context = JXPathContext.newContext(container);
        String expr = "/studentClass/student_list/student[@id='1']";
        context.getValue(expr);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid expression.", expr, operation.getExpression());
        Assert.assertEquals("Invalid method name.", "getValue", operation.getMethodName());
    }

    @Test
    public void testIterate() {
        URL url = JXPathTest.class.getResource("/students.xml");

        Container container = new DocumentContainer(url);

        JXPathContext context = JXPathContext.newContext(container);
        String expr = "/studentClass";
        context.iterate(expr);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid expression.", expr, operation.getExpression());
        Assert.assertEquals("Invalid method name.", "iterate", operation.getMethodName());
    }

    @Test
    public void testRemovePath() {
        URL url = JXPathTest.class.getResource("/students.xml");

        Container container = new DocumentContainer(url);

        JXPathContext context = JXPathContext.newContext(container);
        String expr = "/studentClass/student_list/student[@id='1']";
        context.removePath(expr);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid expression.", expr, operation.getExpression());
        Assert.assertEquals("Invalid method name.", "removePath", operation.getMethodName());
    }

    @Test
    public void testRemoveAll() {
        URL url = JXPathTest.class.getResource("/students.xml");

        Container container = new DocumentContainer(url);

        JXPathContext context = JXPathContext.newContext(container);
        String expr = "/studentClass/student_list/student[@id='2']";
        context.removeAll(expr);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        XPathOperation operation = (XPathOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.XPATH, operation.getCaseType());
        Assert.assertEquals("Invalid expression.", expr, operation.getExpression());
        Assert.assertEquals("Invalid method name.", "removeAll", operation.getMethodName());
    }
}
