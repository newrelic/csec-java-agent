package com.nr.agent.security.instrumentation.javax.ldap;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.LDAPOperation;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.zapodot.junit.ldap.EmbeddedLdapRule;
import org.zapodot.junit.ldap.EmbeddedLdapRuleBuilder;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapName;
import java.util.Hashtable;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.naming" } )
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DirContextTest {
    public static final String DOMAIN_DSN = "dc=example,dc=com";
    @ClassRule
    public static EmbeddedLdapRule embeddedLdapRule = EmbeddedLdapRuleBuilder.newInstance().usingDomainDsn(DOMAIN_DSN)
            .importingLdifs("users-import.ldif").build();

    @BeforeClass
    public static void setup() throws LDAPException {
        LDAPInterface ldapConnection = embeddedLdapRule.ldapConnection();
    }

    @Test
    public void testSearchWithLdapContext() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";
        String password = "abc456";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            InitialLdapContext ctx = new InitialLdapContext(env, null);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(DOMAIN_DSN, query, constraints);

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected.", operations.isEmpty());
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", InitialLdapContext.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithLdapContext1() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";
        String password = "123efg";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            InitialLdapContext ctx = new InitialLdapContext(env, null);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(new LdapName(DOMAIN_DSN), query, constraints);

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected.", operations.isEmpty());
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", InitialLdapContext.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithLdapContext2() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "123efg";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            InitialLdapContext ctx = new InitialLdapContext(env, null);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(new LdapName(DOMAIN_DSN), new BasicAttributes());

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations should detected.", operations.isEmpty());
    }

    @Test
    public void testSearchWithLdapContext3() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";
        String password = "abc456";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            InitialLdapContext ctx = new InitialLdapContext(env, null);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(DOMAIN_DSN, new BasicAttributes());

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.isEmpty());
    }

    @Test
    public void testSearchWithLdapContext4() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            InitialLdapContext ctx = new InitialLdapContext(env, null);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(DOMAIN_DSN, query, new Object[]{}, constraints);

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected.", operations.isEmpty());
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", InitialLdapContext.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithLdapContext5() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "abc456";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            InitialLdapContext ctx = new InitialLdapContext(env, null);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(new LdapName(DOMAIN_DSN), query, new Object[]{}, constraints);

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected.", operations.isEmpty());
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", InitialLdapContext.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithDirContext() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";
        String password = "abc456";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            DirContext ctx = new InitialDirContext(env);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(DOMAIN_DSN, query, constraints);

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected.", operations.isEmpty());
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", InitialDirContext.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithDirContext1() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";
        String password = "123efg";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            DirContext ctx = new InitialDirContext(env);
    
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(new LdapName(DOMAIN_DSN), query, constraints);

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected.", operations.isEmpty());
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", InitialDirContext.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithDirContext2() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "123efg";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            DirContext ctx = new InitialDirContext(env);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(new LdapName(DOMAIN_DSN), new BasicAttributes());

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations should detected.", operations.isEmpty());
    }

    @Test
    public void testSearchWithDirContext3() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";
        String password = "abc456";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            DirContext ctx = new InitialDirContext(env);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(DOMAIN_DSN, new BasicAttributes());

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations should detected.", operations.isEmpty());
    }

    @Test
    public void testSearchWithDirContext4() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            DirContext ctx = new InitialDirContext(env);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(DOMAIN_DSN, query, new Object[]{}, constraints);

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected.", operations.isEmpty());
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", InitialDirContext.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithDirContext5() throws LDAPException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "abc456";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put("java.naming.provider.url", "ldap://localhost:"+port);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");

        try {
            DirContext ctx = new InitialDirContext(env);

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[0]);      //return no attrs

            NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(new LdapName(DOMAIN_DSN), query, new Object[]{}, constraints);

            while (results.hasMore()) {
                System.out.println(results.next());
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected.", operations.isEmpty());
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", InitialDirContext.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }
}
