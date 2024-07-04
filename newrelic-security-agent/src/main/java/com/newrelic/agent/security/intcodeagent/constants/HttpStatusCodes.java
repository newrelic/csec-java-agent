package com.newrelic.agent.security.intcodeagent.constants;

import java.util.HashMap;
import java.util.Map;

public class HttpStatusCodes {

    public static Map<Integer, String> codes = new HashMap<>();

    static {
        codes.put(200, "OK");
        codes.put(201, "Created");
        codes.put(202, "Accepted");
        codes.put(203, "Non-Authoritative Information");
        codes.put(204, "No Content");
        codes.put(205, "Reset Content");
        codes.put(206, "Partial Content");
        codes.put(207, "Multi-Status");
        codes.put(208, "Already Reported");
        codes.put(209, "IM Used");
        codes.put(300, "Multiple Choices");
        codes.put(301, "Moved Permanently");
        codes.put(302, "Found");
        codes.put(303, "See Other");
        codes.put(304, "Not Modified");
        codes.put(305, "Use Proxy");
        codes.put(307, "Temporary Redirect");
        codes.put(400, "Bad Request");
        codes.put(401, "Unauthorized");
        codes.put(402, "Payment Required");
        codes.put(403, "Forbidden");
        codes.put(404, "Not Found");
        codes.put(405, "Method Not Allowed");
        codes.put(406, "Not Acceptable");
        codes.put(407, "Proxy Authentication Required");
        codes.put(408, "Request Timeout");
        codes.put(409, "Conflict");
        codes.put(410, "Gone");
        codes.put(411, "Length Required");
        codes.put(412, "Precondition Failed");
        codes.put(413, "Request Entity Too Large");
        codes.put(414, "Request-URI Too Long");
        codes.put(415, "Unsupported Media Type");
        codes.put(416, "Requested Range Not Satisfiable");
        codes.put(417, "Expectation Failed");
        codes.put(500, "Internal Server Error");
        codes.put(501, "Not Implemented");
        codes.put(502, "Bad Gateway");
        codes.put(503, "Service Unavailable");
        codes.put(504, "Gateway Timeout");
        codes.put(505, "HTTP Version Not Supported");
        codes.put(506, "Variant Also Negotiates");
        codes.put(507, "Insufficient Storage");
        codes.put(508, "Loop Detected");
        codes.put(510, "Not Extended");
        codes.put(511, "Network Authentication Required");

    }

    public static String getStatusCode(int code) {
        return codes.get(code);
    }
}
