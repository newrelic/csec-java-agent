package com.nr.agent.security.instrumentation.memcached.test;

import com.github.mwarc.embeddedmemcached.JMemcachedServer;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.MemcachedOperation;
import net.spy.memcached.MemcachedClient;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "net.spy.memcached" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MemcachedTest {

    private static MemcachedClient memcachedClient;
    private final String key = "someKey";
    private final String value = "value";
    private final int expirationInSeconds = 1800;
    private final long casID = 1;
    private static JMemcachedServer server;

    @BeforeClass
    public static void setup() throws IOException {
        server = new JMemcachedServer();
        server.start("127.0.0.1", 11214);
        memcachedClient = new MemcachedClient(new InetSocketAddress("127.0.0.1", 11214));
    }

    @AfterClass
    public static void stop() {
        memcachedClient.flush();
        memcachedClient.shutdown();
        server.clean();
    }
    @Test
    public void setTest() {
        memcachedClient.set(key, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncStore", operation.getMethodName());
    }
    @Test
    public void addTest() {
        memcachedClient.add(key, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncStore", operation.getMethodName());
    }
    @Test
    public void replaceTest() {
        memcachedClient.replace(key, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncStore", operation.getMethodName());
    }
    @Test
    public void appendTest() {
        memcachedClient.append(key, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncCat", operation.getMethodName());
    }
    @Test
    public void prependTest() {
        memcachedClient.prepend(key, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncCat", operation.getMethodName());
    }
    @Test
    public void prependTest1() {
        memcachedClient.prepend(casID, key, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncCat", operation.getMethodName());
    }
    @Test
    public void casTest() {
        memcachedClient.cas(key, casID, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncCAS", operation.getMethodName());
    }
    @Test
    public void casTest1() {
        memcachedClient.cas(key, casID, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncCAS", operation.getMethodName());
    }

    @Test
    public void asyncCASTest() {
        memcachedClient.asyncCAS(key, casID, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncCAS", operation.getMethodName());
    }
    @Test
    public void asyncCASTest1() {
        memcachedClient.asyncCAS(key, casID, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        Assert.assertEquals("Invalid executed key.", key, operation.getKey());
        Assert.assertEquals("Invalid executed value.", value, operation.getValue());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.MEMCACHED, operation.getCaseType());
        Assert.assertEquals("Invalid executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method-name.", "asyncCAS", operation.getMethodName());
    }
}
