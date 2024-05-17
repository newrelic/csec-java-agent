package com.newrelic.api.agent.security.schema;

import java.io.Serializable;
import java.util.List;

public class ControlCommandDto implements Serializable {
    private String id;
    private FuzzRequestBean requestBean;
    private List<String> payloads;

    public String getId() {
        return id;
    }

    public FuzzRequestBean getRequestBean() {
        return requestBean;
    }

    public List<String> getRequestPayloads() {
        return payloads;
    }

    public ControlCommandDto(String id, FuzzRequestBean requestBean, List<String> payloads) {
        this.id = id;
        this.requestBean = requestBean;
        this.payloads = payloads;
    }
}