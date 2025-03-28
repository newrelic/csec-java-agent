package com.newrelic.agent.security.instrumentation.httpclient3;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;

public class SecurityHelper {

    public static final String METHOD_NAME_EXECUTE = "execute";
    public static final String NULL_STRING = "null";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SSRF_OPERATION_LOCK_APACHE_COMMONS-";
    public static final String HTTP_CLIENT_3 = "HTTP_CLIENT-3";

    public static String getURI(String scheme, String host, int port, String path) {
        StringBuilder sb = new StringBuilder();
        if (scheme != null) {
            sb.append(scheme);
            sb.append("://");
        }
        if (host != null) {
            sb.append(host);
            if (port >= 0) {
                sb.append(":");
                sb.append(port);
            }
        }
        if (path != null) {
            sb.append(path);
        }
        return sb.toString();
    }

    public static String getParentId(){
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
    }
}
