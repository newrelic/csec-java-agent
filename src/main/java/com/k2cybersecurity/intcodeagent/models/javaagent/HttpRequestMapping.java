package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.util.HashMap;
import java.util.Map;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class HttpRequestMapping {

    private String id;

    private HttpRequestBean baseRequest;

    private HttpRequestBean referentialRequest;

    private Map<String, UserValue> userValueMap;
    
    public HttpRequestMapping() {
	}

    public HttpRequestMapping(String id, HttpRequestBean baseRequest, HttpRequestBean referentialRequest) {
        this.id = id;
        this.baseRequest = baseRequest;
        this.referentialRequest = referentialRequest;
        this.userValueMap = new HashMap<>();
    }

    public HttpRequestBean getBaseRequest() {
        return baseRequest;
    }

    public void setBaseRequest(HttpRequestBean baseRequest) {
        this.baseRequest = baseRequest;
    }

    public HttpRequestBean getReferentialRequest() {
        return referentialRequest;
    }

    public void setReferentialRequest(HttpRequestBean referentialRequest) {
        this.referentialRequest = referentialRequest;
    }

    public Map<String, UserValue> getUserValueMap() {
        return userValueMap;
    }

    public void setUserValueMap(Map<String, UserValue> userValueMap) {
        this.userValueMap = userValueMap;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String toString() {
    	return JsonConverter.toJSON(this);
    }
}
