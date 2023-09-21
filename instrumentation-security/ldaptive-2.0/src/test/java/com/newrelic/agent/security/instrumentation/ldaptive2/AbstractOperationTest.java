package com.newrelic.agent.security.instrumentation.ldaptive2;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.LDAPOperation;
import com.newrelic.security.test.marker.Java8IncompatibleTest;
import com.newrelic.security.test.marker.Java9IncompatibleTest;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.PooledConnectionFactory;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResponse;
import org.zapodot.junit.ldap.EmbeddedLdapRule;
import org.zapodot.junit.ldap.EmbeddedLdapRuleBuilder;

import java.util.List;

@Category({ Java8IncompatibleTest.class, Java9IncompatibleTest.class })
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "org.ldaptive", "com.newrelic.agent.security.instrumentation.ldaptive2.LDAPUtils" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AbstractOperationTest {
    public static final String DOMAIN_DSN = "dc=example,dc=com";
    @ClassRule
    public static EmbeddedLdapRule embeddedLdapRule = EmbeddedLdapRuleBuilder.newInstance().usingDomainDsn(DOMAIN_DSN)
            .importingLdifs("users-import.ldif").build();

    @Test
    public void testSearch() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";
        String password = "123efg";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        SearchOperation search = new SearchOperation(new DefaultConnectionFactory("ldap://localhost:"+port+"/dc=example,dc=com"));
        SearchResponse response = search.execute(query);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

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
    public void testSearch1() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";
        String password = "abc456";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        SearchOperation search = new SearchOperation(new DefaultConnectionFactory("ldap://localhost:"+port), DOMAIN_DSN);
        SearchResponse response = search.execute(query);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "configureRequest", operation.getMethodName());
    }

    @Test
    public void testSearch2() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "abc456";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        SearchRequest sr = new SearchRequest(DOMAIN_DSN, query);
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(new DefaultConnectionFactory("ldap://localhost:"+port), sr);
        SearchResponse response = search.execute();
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "configureRequest", operation.getMethodName());
    }

    @Test
    public void testSearch3() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);

        SearchRequest sr = new SearchRequest(DOMAIN_DSN);
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(new DefaultConnectionFactory("ldap://localhost:"+port), sr);
        SearchResponse response = search.execute(query);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "configureRequest", operation.getMethodName());
    }

    @Test
    public void testSearch4() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "123efg";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        SearchRequest sr = new SearchRequest();
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(new DefaultConnectionFactory("ldap://localhost:"+port+"/dc=example,dc=com"), sr);
        SearchResponse response = search.execute(query);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

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
    public void testSearch5() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "123efg";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        SearchRequest sr = new SearchRequest(DOMAIN_DSN, query);
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(new DefaultConnectionFactory("ldap://localhost:"+port));
        SearchResponse response = search.execute(sr);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
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

        PooledConnectionFactory pool = new PooledConnectionFactory("ldap://localhost:"+port+"/dc=example,dc=com");
        pool.initialize();
        SearchOperation search = new SearchOperation(pool);
        SearchResponse response = search.execute(query);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

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
    public void testSearchWithConnPool1() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";
        String password = "abc456";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        PooledConnectionFactory pool = new PooledConnectionFactory("ldap://localhost:"+port);
        pool.initialize();
        SearchOperation search = new SearchOperation(pool, DOMAIN_DSN);
        SearchResponse response = search.execute(query);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "configureRequest", operation.getMethodName());
    }

    @Test
    public void testSearchWithConnPool2() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "abc456";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        PooledConnectionFactory pool = new PooledConnectionFactory("ldap://localhost:"+port);
        pool.initialize();
        SearchRequest sr = new SearchRequest(DOMAIN_DSN, query);
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(pool, sr);
        SearchResponse response = search.execute();
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "configureRequest", operation.getMethodName());
    }

    @Test
    public void testSearchWithConnPool3() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "mlakshkar";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);

        PooledConnectionFactory pool = new PooledConnectionFactory("ldap://localhost:"+port);
        pool.initialize();
        SearchRequest sr = new SearchRequest(DOMAIN_DSN);
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(pool, sr);
        SearchResponse response = search.execute(query);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "configureRequest", operation.getMethodName());
    }

    @Test
    public void testSearchWithConnPool4() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "123efg";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        PooledConnectionFactory pool = new PooledConnectionFactory("ldap://localhost:"+port+"/"+DOMAIN_DSN);
        pool.initialize();
        SearchRequest sr = new SearchRequest();
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(pool, sr);
        SearchResponse response = search.execute(query);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

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
    public void testSearchWithConnPool5() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String password = "123efg";

        String query = String.format("(&(userPassword=%s))", password);
        System.out.println("LDAP query: " + query);

        PooledConnectionFactory pool = new PooledConnectionFactory("ldap://localhost:"+port);
        pool.initialize();
        SearchRequest sr = new SearchRequest(DOMAIN_DSN, query);
        sr.setReturnAttributes("cn");
        SearchOperation search = new SearchOperation(pool);
        SearchResponse response = search.execute(sr);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "configureRequest", operation.getMethodName());
    }

    @Test
    public void testExecute() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";
        String password = "123efg";

        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);
        System.out.println("LDAP query: " + query);

        SearchOperation search = new SearchOperation(new DefaultConnectionFactory("ldap://localhost:"+port));
        SearchResponse response = search.execute(DOMAIN_DSN, query, null, null);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);
        Assert.assertEquals("Invalid executed baseDn.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", SearchOperation.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "configureRequest", operation.getMethodName());
    }

    @Test
    public void testExecute1() throws LdapException {
        int port = embeddedLdapRule.embeddedServerPort();
        String username = "sclaus";

        String query = String.format("(&(uid=%s))", username);
        System.out.println("LDAP query: " + query);

        SearchOperation search = new SearchOperation(new DefaultConnectionFactory("ldap://localhost:"+port+"/"+DOMAIN_DSN));
        SearchResponse response = search.execute(query, null, null);
        LdapEntry result = response.getEntry();
        System.out.println("Name: " + result.getAttribute("cn").getStringValue());

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
}
