package com.nr.agent.security.instrumentation.javax.jndi;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import javax.naming.JNDIUtils;

import com.newrelic.security.test.marker.Java11IncompatibleTest;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import com.newrelic.security.test.marker.Java21IncompatibleTest;
import com.newrelic.security.test.marker.Java23IncompatibleTest;
import com.newrelic.security.test.marker.Java9IncompatibleTest;
import com.unboundid.ldap.sdk.LDAPException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.zapodot.junit.ldap.EmbeddedLdapRule;
import org.zapodot.junit.ldap.EmbeddedLdapRuleBuilder;

import javax.naming.CompositeName;
import javax.naming.CompoundName;
import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.naming", "com.newrelic.agent.security.instrumentation.javax.jndi" } )
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ Java9IncompatibleTest.class, Java11IncompatibleTest.class, Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class ContextTest {
    public static final String DOMAIN_DSN = "dc=example,dc=com";
    @ClassRule
    public static EmbeddedLdapRule embeddedLdapRule = EmbeddedLdapRuleBuilder.newInstance()
            .usingDomainDsn(DOMAIN_DSN)
            .importingLdifs("users-import.ldif")
            .build();
    private final int PORT = embeddedLdapRule.embeddedServerPort();
    private final String LDAP_URL = String.format("ldap://localhost:%d/%s", PORT, DOMAIN_DSN);
    private final String DNS_URL = "dns://8.8.8.8/";
    private final String LDAP_CTX_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    @BeforeClass
    public static void setup() throws LDAPException {
        embeddedLdapRule.ldapConnection();
    }
    @Test
    public void testLookupString() throws Exception {

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, LDAP_URL);

        DirContext ctx = new InitialDirContext(env);
        ctx.lookup(LDAP_URL);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", LDAP_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }

    @Test
    public void testLookupLinkString() throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, LDAP_URL);

        DirContext ctx = new InitialDirContext(env);
        ctx.lookupLink(LDAP_URL);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", LDAP_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupName() throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, LDAP_URL);

        DirContext ctx = new InitialDirContext(env);
        ctx.lookup(new CompositeName().add(LDAP_URL));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", LDAP_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupLinkName() throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, LDAP_URL);

        DirContext ctx = new InitialDirContext(env);
        ctx.lookupLink(new CompositeName().add(LDAP_URL));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", LDAP_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }

    @Test
    public void testLookupName1() throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, LDAP_URL);

        DirContext ctx = new InitialDirContext(env);
        ctx.lookup(new CompoundName(LDAP_URL, new Properties()));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", LDAP_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }

    @Test
    public void testLookupLinkName1() throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, LDAP_URL);

        DirContext ctx = new InitialDirContext(env);
        ctx.lookupLink(new CompoundName(LDAP_URL, new Properties()));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", LDAP_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupString1() throws Exception {
        DirContext ctx = new InitialDirContext();
        ctx.lookup(LDAP_URL);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", LDAP_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupLinkString1() throws Exception {

        DirContext ctx = new InitialDirContext();
        ctx.lookupLink(DNS_URL);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", DNS_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupName2() throws Exception {

        DirContext ctx = new InitialDirContext();
        ctx.lookup(new CompositeName().add(DNS_URL));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", DNS_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupLinkName2() throws Exception {

        DirContext ctx = new InitialDirContext();
        ctx.lookupLink(new CompositeName().add(DNS_URL));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", DNS_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupName3() throws Exception {

        DirContext ctx = new InitialDirContext();
        ctx.lookup(new CompoundName(DNS_URL, new Properties()));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", DNS_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
    @Test
    public void testLookupLinkName3() throws Exception {

        DirContext ctx = new InitialDirContext();
        ctx.lookupLink(new CompoundName(DNS_URL, new Properties()));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid method name", JNDIUtils.METHOD_LOOKUP, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed parameters", DNS_URL, operation.getArg());
        Assert.assertTrue("JNDILookup flag should be true", operation.isJNDILookup());
    }
}
