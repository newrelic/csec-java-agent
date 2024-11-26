package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.api.agent.security.schema.http.RequestLayout;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class CommunicationApis {

    public static final String GET_POLICY = "getPolicy";

    public static final Map<String, RequestLayout> REQUEST_CONFIG = Collections.unmodifiableMap(
            new HashMap<String, RequestLayout>() {{
                put(GET_POLICY, new RequestLayout(GET_POLICY));
            }}
    );

    public static RequestLayout get(String api) {
        RequestLayout result = REQUEST_CONFIG.get(api);
        if(result == null) {
            //TODO throw exception
        }
        return result;
    }

}
