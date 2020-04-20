package com.k2cybersecurity.instrumentator.decorators.ldaplibs;

public interface ILDAPConstants {
	String UNBOUNDID_IN_MEMORY = "public com.unboundid.ldap.sdk.SearchResult com.unboundid.ldap.listener.InMemoryDirectoryServer.search(com.unboundid.ldap.sdk.SearchRequest) throws com.unboundid.ldap.sdk.LDAPSearchException";
	String UNBOUNDID_LDAP_CONNECTION = "public com.unboundid.ldap.sdk.SearchResult com.unboundid.ldap.sdk.LDAPConnection.search(com.unboundid.ldap.sdk.SearchRequest) throws com.unboundid.ldap.sdk.LDAPSearchException";
	String APACHE_LDAP_1 = "public org.apache.directory.server.core.filtering.EntryFilteringCursor org.apache.directory.server.core.DefaultOperationManager.search(org.apache.directory.server.core.interceptor.context.SearchOperationContext) throws java.lang.Exception";
	String APACHE_LDAP_2 = "public org.apache.directory.server.core.api.filtering.EntryFilteringCursor org.apache.directory.server.core.DefaultOperationManager.search(org.apache.directory.server.core.api.interceptor.context.SearchOperationContext) throws org.apache.directory.api.ldap.model.exception.LdapException";
	String LDAPTIVE_EXECUTE = "public org.ldaptive.SearchResponse org.ldaptive.SearchOperation.execute(org.ldaptive.SearchRequest) throws org.ldaptive.LdapException";
}
