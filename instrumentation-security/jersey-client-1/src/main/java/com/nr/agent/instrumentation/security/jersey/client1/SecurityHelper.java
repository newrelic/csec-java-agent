package com.nr.agent.instrumentation.security.jersey.client1;

public class SecurityHelper {

    public static final String METHOD_NAME_HANDLE = "handle";
    public static final String NULL_STRING = "null";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SSRF_OPERATION_LOCK_JERSEY1-";

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
