package com.nr.agent.instrumentation.security.httpclient50;

public class SecurityHelper {

    public static final String METHOD_NAME_EXECUTE = "execute";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SSRF_OPERATION_LOCK_APACHE5-";

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
}
