package com.newrelic.agent.security.instrumentation.apache.ldap;

public class LDAPUtils {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "LDAP_OPERATION_LOCK_APACHE-";
    public static final String METHOD_SEARCH = "search";

    public static final String METHOD_SEARCH_ASYNC = "searchAsync";
    public static final String APACHE_LDAP = "APACHE-LDAP";
}
