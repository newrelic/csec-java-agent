package com.newrelic.agent.security.instrumentation.javax.ldap;

public class LDAPUtils {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "LDAP_OPERATION_LOCK-";
    public static final String METHOD_SEARCH = "search";
    public static final Object JAVAX_LDAP = "JAVAX-LDAP";
}
