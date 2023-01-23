package com.nr.instrumentation.security.unboundid.ldap.sdk;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.LDAPOperation;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.zapodot.junit.ldap.EmbeddedLdapRule;
import org.zapodot.junit.ldap.EmbeddedLdapRuleBuilder;

import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.unboundid.ldap.sdk", "com.nr.instrumentation.security.unboundid.ldap.LDAPUtils" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LDAPInterfaceTest {
    public static final String DOMAIN_DSN = "dc=example,dc=com";
    @ClassRule
    public static EmbeddedLdapRule embeddedLdapRule = EmbeddedLdapRuleBuilder.newInstance().usingDomainDsn(DOMAIN_DSN)
            .importingLdifs("users-import.ldif").build();
    private LDAPInterface ldapConnection;

    @Test
    public void testSearch() throws Exception {
        String filter = "(objectClass=person)";
        ldapConnection = embeddedLdapRule.ldapConnection();
        final SearchResult searchResult = ldapConnection.search(DOMAIN_DSN, SearchScope.SUB, filter);

        List<SearchResultEntry> searchEntries = searchResult.getSearchEntries();
        System.out.println(searchEntries.get(0).getAttribute("cn").getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", filter, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.unboundid.ldap.sdk.LDAPConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearch1() throws Exception {
        String baseDN = "cn=Santa Claus,ou=Users,dc=example,dc=com";
        String filter = "(objectClass=person)";
        ldapConnection = embeddedLdapRule.ldapConnection();
        final SearchResult searchResult = ldapConnection.search(baseDN, SearchScope.SUB, filter);
        System.out.println(searchResult.getSearchEntries().get(0).getAttribute("cn").getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", baseDN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", filter, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.unboundid.ldap.sdk.LDAPConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearch2() throws Exception {
        String baseDN = "cn=Monu Lakshkar,ou=Users,dc=example,dc=com";
        String filter = "(objectClass=person)";
        ldapConnection = embeddedLdapRule.ldapConnection();

        SearchRequest request = new SearchRequest(baseDN, SearchScope.SUB, filter);
        final SearchResult searchResult = ldapConnection.search(request);
        System.out.println(searchResult.getSearchEntries().get(0).getAttribute("cn").getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", baseDN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", filter, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.unboundid.ldap.sdk.LDAPConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithFilter() throws Exception {
        String baseDN = "cn=Santa Claus,ou=Users,dc=example,dc=com";
        String filter = "(objectClass=person)";
        ldapConnection = embeddedLdapRule.ldapConnection();
        final SearchResult searchResult = ldapConnection.search(baseDN, SearchScope.SUB, Filter.create(filter));
        System.out.println(searchResult.getSearchEntries().get(0).getAttribute("cn").getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", baseDN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", filter, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.unboundid.ldap.sdk.LDAPConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithFilter1() throws Exception {
        String username = "mlakshkar";
        String password = "abc456";
        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);

        ldapConnection = embeddedLdapRule.ldapConnection();
        final SearchResult searchResult = ldapConnection.search(DOMAIN_DSN, SearchScope.SUB, Filter.create(query));
        System.out.println(searchResult.getSearchEntries().get(0).getAttribute("cn").getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.unboundid.ldap.sdk.LDAPConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchWithFilter2() throws Exception {
        String username = "mlakshkar";
        String query = String.format("(&(uid=%s))", username);

        ldapConnection = embeddedLdapRule.ldapConnection();
        SearchRequest request = new SearchRequest(DOMAIN_DSN, SearchScope.SUB, Filter.create(query));
        final SearchResult searchResult = ldapConnection.search(request);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.unboundid.ldap.sdk.LDAPConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchForEntry() throws Exception {
        String username = "mlakshkar";
        String password = "abc456";
        String query = String.format("(&(uid=%s)(userPassword=%s))", username, password);

        ldapConnection = embeddedLdapRule.ldapConnection();
        final SearchResultEntry searchResult = ldapConnection.searchForEntry(DOMAIN_DSN, SearchScope.SUB, query, null);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.unboundid.ldap.sdk.LDAPConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchForEntry1() throws Exception {
        String username = "mlakshkar";
        String query = String.format("(&(uid=%s))", username);

        ldapConnection = embeddedLdapRule.ldapConnection();
        final SearchResultEntry searchResult = ldapConnection.searchForEntry(DOMAIN_DSN, SearchScope.SUB, Filter.create(query), null);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.unboundid.ldap.sdk.LDAPConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }

    @Test
    public void testSearchForEntry2() throws Exception {
        String password = "abc456";
        String query = String.format("(&(userPassword=%s))", password);

        ldapConnection = embeddedLdapRule.ldapConnection();
        SearchRequest request = new SearchRequest(DOMAIN_DSN, SearchScope.SUB, Filter.create(query));
        final SearchResultEntry searchResult = ldapConnection.searchForEntry(request);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        LDAPOperation operation = (LDAPOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", DOMAIN_DSN, operation.getName());
        Assert.assertEquals("Invalid executed parameters.", query, operation.getFilter());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.LDAP, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "com.unboundid.ldap.sdk.LDAPConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "search", operation.getMethodName());
    }
}
