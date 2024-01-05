package com.newrelic.api.agent.security.instrumentation.helpers;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GrpcHelper {
    public static final String NR_SEC_GRPC_REQUEST_DATA = "nr-sec-grpc-request-data";
    public static final String NR_SEC_GRPC_RESPONSE_DATA = "nr-sec-grpc-response-data";
    public static final String NR_SEC_GRPC_REQUEST_DATA_TYPE = "nr-sec-grpc-request-message";
    public static final String NR_SEC_GRPC_RESPONSE_DATA_TYPE = "nr-sec-grpc-response-message";
    public static final String REQUEST_TYPE = "nr-sec-grpc-request-type";

    public static String getFormattedIp(String input) {
        Pattern ipv4Regex = Pattern.compile("(\\d{1,3}\\.){3}\\d{1,3}");
        Pattern ipv6Regex = Pattern.compile("([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}");

        Matcher ipv4 = ipv4Regex.matcher(input);
        if (ipv4.find()) {
            return ipv4.group();
        }

        Matcher ipv6 = ipv6Regex.matcher(input);
        if (ipv6.find()) {
            return ipv6.group();
        }

        return "";
    }

    public static String getPort(String input) {
        String[] strings = input.split(":");
        return strings[strings.length-1];
    }
}
