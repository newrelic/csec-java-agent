package com.nr.agent.security.instrumentation.javax.jndi;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import javax.naming.JNDIUtils;

import com.newrelic.security.test.marker.*;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import javax.naming.CompositeName;
import javax.naming.CompoundName;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.IOException;
import java.net.ServerSocket;
import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.util.List;
import java.util.Properties;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.naming", "com.newrelic.agent.security.instrumentation.javax.jndi" } )
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ Java9IncompatibleTest.class, Java11IncompatibleTest.class, Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class ContextRmiTest {

    private final int PORT = getRandomPort();
    private final String RMI_URL = "rmi://localhost:"+PORT+"/test";

    @Test
    public void testLookupString() throws Exception {
        RmiServer server = new RmiServer();
        LocateRegistry.createRegistry(PORT);
        Naming.rebind(RMI_URL, server);

        DirContext ctx = new InitialDirContext();
        ctx.lookup(RMI_URL);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", RMI_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupLinkString() throws Exception {
        RmiServer server = new RmiServer();
        LocateRegistry.createRegistry(PORT);
        Naming.rebind(RMI_URL, server);

        DirContext ctx = new InitialDirContext();
        ctx.lookupLink(RMI_URL);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", RMI_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupName() throws Exception {
        RmiServer server = new RmiServer();
        LocateRegistry.createRegistry(PORT);
        Naming.rebind(RMI_URL, server);

        DirContext ctx = new InitialDirContext();
        ctx.lookup(new CompositeName().add(RMI_URL));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", RMI_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupLinkName() throws Exception {
        RmiServer server = new RmiServer();
        LocateRegistry.createRegistry(PORT);
        Naming.rebind(RMI_URL, server);

        DirContext ctx = new InitialDirContext();
        ctx.lookupLink(new CompositeName().add(RMI_URL));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", RMI_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupName1() throws Exception {
        RmiServer server = new RmiServer();
        LocateRegistry.createRegistry(PORT);
        Naming.rebind(RMI_URL, server);

        DirContext ctx = new InitialDirContext();
        ctx.lookup(new CompoundName(RMI_URL, new Properties()));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", RMI_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupLinkName1() throws Exception {
        RmiServer server = new RmiServer();
        LocateRegistry.createRegistry(PORT);
        Naming.rebind(RMI_URL, server);

        DirContext ctx = new InitialDirContext();
        ctx.lookupLink(new CompoundName(RMI_URL, new Properties()));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", RMI_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }

    private int getRandomPort() {
        int port;

        try {
            ServerSocket socket = new ServerSocket(0);
            port = socket.getLocalPort();
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port");
        }
        return port;
    }
    private static class RmiServer extends UnicastRemoteObject implements Remote {
        protected RmiServer() throws RemoteException {}
    }
}
