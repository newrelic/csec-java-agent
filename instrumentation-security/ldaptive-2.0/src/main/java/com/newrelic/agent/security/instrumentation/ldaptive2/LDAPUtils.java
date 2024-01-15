package com.newrelic.agent.security.instrumentation.ldaptive2;

public class LDAPUtils {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "LDAP_OPERATION_LOCK_LDAPTIVE-";
    public static final String METHOD_CONFIGURE_REQUEST = "configureRequest";

    public static final String NR_SEC_CUSTOM_ATTR_FILTER_NAME = "LDAP_FILTER-";
    public static final String LDAPTIVE_2_0 = "LDAPTIVE-2.0";

    public static String getNrSecCustomAttribName(int hashCode) {
        return NR_SEC_CUSTOM_ATTR_FILTER_NAME + hashCode;
    }
}
