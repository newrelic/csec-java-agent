package com.nr.instrumentation.security.ldaptive1;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.LDAPOperation;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapException;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResult;
import org.ldaptive.pool.BlockingConnectionPool;
import org.ldaptive.pool.PooledConnectionFactory;
import org.zapodot.junit.ldap.EmbeddedLdapRule;
import org.zapodot.junit.ldap.EmbeddedLdapRuleBuilder;

import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "org.ldaptive", "com.nr.instrumentation.security.apache.ldap.LDAPUtils" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AbstractOperationTest {
    public static final String DOMAIN_DSN = "dc=example,dc=com";
    @ClassRule
    public static EmbeddedLdapRule embeddedLdapRule = EmbeddedLdapRuleBuilder.newInstance().usingDomainDsn(DOMAIN_DSN)
            .importingLdifs("users-import.ldif").build();

    @Test
    public void testSearch() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";
        String password = "abc456";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);
        DefaultConnectionFactory cf = new DefaultConnectionFactory(config);
        Connection conn = cf.getConnection();

        conn.open();

        SearchRequest sr = new SearchRequest("dc=example,dc=com", query);
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(conn);

        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "invoke", operation.getMethodName());
    }

    @Test
    public void testSearch1() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "abc456";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);
        DefaultConnectionFactory cf = new DefaultConnectionFactory(config);
        Connection conn = cf.getConnection();

        conn.open();

        SearchRequest sr = new SearchRequest("dc=example,dc=com", query, "cn");
        SearchOperation search = new SearchOperation(conn);

        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "invoke", operation.getMethodName());
    }

    @Test
    public void testSearch2() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);

        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);
        DefaultConnectionFactory cf = new DefaultConnectionFactory(config);
        Connection conn = cf.getConnection();

        conn.open();

        SearchRequest sr = new SearchRequest("dc=example,dc=com", new SearchFilter(query));
        SearchOperation search = new SearchOperation(conn);

        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "invoke", operation.getMethodName());
    }

    @Test
    public void testSearch3() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);

        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);
        DefaultConnectionFactory cf = new DefaultConnectionFactory(config);
        Connection conn = cf.getConnection();

        conn.open();

        SearchRequest sr = new SearchRequest("dc=example,dc=com", new SearchFilter(query), "cn");
        SearchOperation search = new SearchOperation(conn);

        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "invoke", operation.getMethodName());
    }

    @Test
    public void testSearch4() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";
        String password = "123efg";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);
        DefaultConnectionFactory cf = new DefaultConnectionFactory(config);
        Connection conn = cf.getConnection();

        conn.open();

        SearchRequest sr = new SearchRequest();
        sr.setSearchFilter(new SearchFilter(query));
        SearchOperation search = new SearchOperation(conn);
        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", "", operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "configureRequest", operation.getMethodName());
    }

    @Test
    public void testSearchWithConnPool() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";
        String password = "123efg";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);
        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);

        config.setConnectionInitializer(new BindConnectionInitializer());
        BlockingConnectionPool pool = new BlockingConnectionPool(new DefaultConnectionFactory(config));
        pool.initialize();
        PooledConnectionFactory connFactory = new PooledConnectionFactory(pool);

        Connection conn = connFactory.getConnection();
        conn.open();

        SearchRequest sr = new SearchRequest("dc=example,dc=com", query);
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(conn);

        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "invoke", operation.getMethodName());
    }

    @Test
    public void testSearchWithConnPool1() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "123efg";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);
        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);

        config.setConnectionInitializer(new BindConnectionInitializer());
        BlockingConnectionPool pool = new BlockingConnectionPool(new DefaultConnectionFactory(config));
        pool.initialize();
        PooledConnectionFactory connFactory = new PooledConnectionFactory(pool);

        Connection conn = connFactory.getConnection();
        conn.open();

        SearchRequest sr = new SearchRequest("dc=example,dc=com", query, "cn");
        SearchOperation search = new SearchOperation(conn);

        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "invoke", operation.getMethodName());
    }

    @Test
    public void testSearchWithConnPool2() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);
        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);

        config.setConnectionInitializer(new BindConnectionInitializer());
        BlockingConnectionPool pool = new BlockingConnectionPool(new DefaultConnectionFactory(config));
        pool.initialize();
        PooledConnectionFactory connFactory = new PooledConnectionFactory(pool);

        Connection conn = connFactory.getConnection();
        conn.open();

        SearchRequest sr = new SearchRequest("dc=example,dc=com", new SearchFilter(query));
        SearchOperation search = new SearchOperation(conn);

        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "invoke", operation.getMethodName());
    }

    @Test
    public void testSearchWithConnPool3() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);
        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);

        config.setConnectionInitializer(new BindConnectionInitializer());
        BlockingConnectionPool pool = new BlockingConnectionPool(new DefaultConnectionFactory(config));
        pool.initialize();
        PooledConnectionFactory connFactory = new PooledConnectionFactory(pool);

        Connection conn = connFactory.getConnection();
        conn.open();

        SearchRequest sr = new SearchRequest("dc=example,dc=com", new SearchFilter(query), "cn");
        SearchOperation search = new SearchOperation(conn);

        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "invoke", operation.getMethodName());
    }

    @Test
    public void testSearchWithConnPool4() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);
        ConnectionConfig config = new ConnectionConfig();
        config.setLdapUrl("ldap://localhost:" + port);

        config.setConnectionInitializer(new BindConnectionInitializer());
        BlockingConnectionPool pool = new BlockingConnectionPool(new DefaultConnectionFactory(config));
        pool.initialize();
        PooledConnectionFactory connFactory = new PooledConnectionFactory(pool);

        Connection conn = connFactory.getConnection();
        conn.open();

        SearchRequest sr = new SearchRequest();
        sr.setSearchFilter(new SearchFilter(query));
        SearchOperation search = new SearchOperation(conn);
        SearchResult result = search.execute(sr).getResult();
        System.out.println("Name: " + result.getEntry().getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", "", operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "invoke", operation.getMethodName());
    }
}
