package com.nr.agent.security.instrumentation.memcached.test;

import com.github.mwarc.embeddedmemcached.JMemcachedServer;
import com.newrelic.agent.security.instrumentation.spy.memcached.MemcachedHelper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.MemcachedOperation;
import net.spy.memcached.MemcachedClient;
import net.spy.memcached.ops.StoreType;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "net.spy.memcached" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MemcachedTest {

    public static final String WRITE = "write";
    public static final String UPDATE = "update";
    private static MemcachedClient memcachedClient;
    private final String key = "someKey";
    private final String value = "value";
    private final int expirationInSeconds = 1800;
    private final long casID = 1;
    private static JMemcachedServer server;
    private static int port = 0;
    private static int getRandomPort() {
        try (ServerSocket socket = new ServerSocket(port)){
            port = socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port "+ port);
        }
        return port;
    }

    @BeforeClass
    public static void setup() throws IOException {
        port = getRandomPort();
        server = new JMemcachedServer();
        server.start("127.0.0.1", port);
        memcachedClient = new MemcachedClient(new InetSocketAddress("127.0.0.1", port));
    }

    @AfterClass
    public static void stop() {
        memcachedClient.flush();
        memcachedClient.shutdown();
        server.clean();
    }
    @Test
    public void testSet() {
        memcachedClient.set(key, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), WRITE, "asyncStore", "set");
    }

    @Test
    public void testAdd() {
        memcachedClient.add(key, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), WRITE, "asyncStore", "add");
    }
    @Test
    public void testReplace() {
        memcachedClient.replace(key, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), WRITE, "asyncStore", "replace");
    }
    @Test
    public void testAppend() {
        memcachedClient.append(key, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), UPDATE, "asyncCat", "append");
    }
    @Test
    public void testPrepend() {
        memcachedClient.prepend(key, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), UPDATE, "asyncCat", "prepend");
    }
    @Test
    public void testPrepend1() {
        memcachedClient.prepend(casID, key, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), UPDATE, "asyncCat", "prepend");
    }
    @Test
    public void testCas() {
        memcachedClient.cas(key, casID, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), WRITE, "asyncCAS", "set");
    }
    @Test
    public void testCas1() {
        memcachedClient.cas(key, casID, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), WRITE, "asyncCAS", "set");
    }

    @Test
    public void testAsyncCAS() {
        memcachedClient.asyncCAS(key, casID, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), WRITE, "asyncCAS", "set");
    }
    @Test
    public void testAsyncCAS1() {
        memcachedClient.asyncCAS(key, casID, expirationInSeconds, value);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("No operations detected.", 1, operations.size());
        MemcachedOperation operation = (MemcachedOperation) operations.get(0);

        verifier(operation, Arrays.asList(key, value), WRITE, "asyncCAS", "set");
    }

    private void verifier(MemcachedOperation operation, List<?> args, String type, String method, String command) {
        Assert.assertEquals("Incorrect executed parameters.", args, operation.getArguments());
        Assert.assertEquals("Incorrect event case type.", VulnerabilityCaseType.CACHING_DATA_STORE, operation.getCaseType());
        Assert.assertEquals("Incorrect event category.", MemcachedOperation.MEMCACHED, operation.getCategory());
        Assert.assertEquals("Incorrect event category.", type, operation.getCommand());
        Assert.assertEquals("Incorrect event category.", command, operation.getType());
        Assert.assertEquals("Incorrect executed class-name.", memcachedClient.getClass().getName(), operation.getClassName());
        Assert.assertEquals("Incorrect executed method-name.", method, operation.getMethodName());
    }
}
