package com.newrelic.agent.security.instrumentation.apache.pekko;

public class PekkoCoreUtils {

    public static final String METHOD_SINGLE_REQUEST = "singleRequest";

    public static final String NR_SEC_CUSTOM_ATTRIB_OUTBOUND_REQ = "OUTBOUND_REQ_OPERATION_LOCK_PEKKO-";
    public static final String NR_SEC_CUSTOM_ATTRIB_HTTP_REQ = "HTTP_REQUEST_OPERATION_LOCK_PEKKO-";

    public static final String PEKKO_HTTP_CORE_2_13_1 = "APACHE_PEKKO_HTTP_CORE_2.13-1";
}
