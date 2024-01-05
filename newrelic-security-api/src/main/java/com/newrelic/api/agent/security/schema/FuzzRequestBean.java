package com.newrelic.api.agent.security.schema;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class FuzzRequestBean extends HttpRequest implements Serializable {
    private Map<String, String> reflectedMetaData;

    public FuzzRequestBean() {
        super();
        reflectedMetaData = new HashMap<>();
    }

    public FuzzRequestBean(FuzzRequestBean servletInfo) {
        super(servletInfo);
        reflectedMetaData = servletInfo.getReflectedMetaData();
    }

    public Map<String, String> getReflectedMetaData() {
        return reflectedMetaData;
    }

    public void setReflectedMetaData(Map<String, String> reflectedMetaData) {
        this.reflectedMetaData = reflectedMetaData;
    }
}