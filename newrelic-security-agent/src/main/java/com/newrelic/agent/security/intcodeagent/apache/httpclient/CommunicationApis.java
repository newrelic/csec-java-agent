package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.api.agent.security.schema.http.RequestLayout;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class CommunicationApis {

    public static final String GET_POLICY = "getPolicy";
    public static final String POST_EVENT = "postEvent";
    public static final String POST_HEALTH_CHECK = "postHealthCheck";
    public static final String GET_HEALTH_CHECK = "getHealthCheck";
    public static final String POST_IAST_DATA_REQUEST = "postIastDataRequest";
    public static final String POST_APPLICATION_INFO = "postApplicationInfo";
    public static final String PING = "ping";

    public static final String POS_ANY = "postAny";

    public static final Map<String, RequestLayout> REQUEST_CONFIG = Collections.unmodifiableMap(
            new HashMap<String, RequestLayout>() {{
                put(GET_POLICY, new RequestLayout(GET_POLICY, "GET", "/v1/policies", "application/json", "utf-8"));
                put(POST_EVENT, new RequestLayout(POST_EVENT, "POST", "/v1/events", "application/json", "gzip"));
                put(POST_HEALTH_CHECK, new RequestLayout(POST_HEALTH_CHECK, "POST", "/v1/healthcheck", "application/json", "gzip"));
                put(GET_HEALTH_CHECK, new RequestLayout(GET_HEALTH_CHECK, "GET", "/v1/healthcheck", "application/json", "utf-8"));
                put(POST_IAST_DATA_REQUEST, new RequestLayout(POST_IAST_DATA_REQUEST, "POST", "/v1/iast/data-request", "application/json", "gzip"));
                put(POST_APPLICATION_INFO, new RequestLayout(POST_APPLICATION_INFO, "POST", "/v1/application-info", "application/json", "gzip"));
                put(PING, new RequestLayout(PING, "GET", "/v1/ping", "application/json", "utf-8"));

                put(POS_ANY, new RequestLayout(POS_ANY, "POST", "/v1/any", "application/json", "utf-8"));
            }}
    );

    public static RequestLayout get(String api) {
        RequestLayout result = REQUEST_CONFIG.get(api);
        if(result == null) {
            throw new IllegalArgumentException("Unknown API: " + api);
        }
        return result;
    }

}
