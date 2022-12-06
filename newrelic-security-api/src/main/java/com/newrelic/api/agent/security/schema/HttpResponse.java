package com.newrelic.api.agent.security.schema;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class HttpResponse {

    private Map<String, String> headers;

    private StringBuilder responseBody;

    private String responseContentType;

    public HttpResponse() {
        this.headers = new ConcurrentHashMap<>();
        this.responseBody = new StringBuilder();
        this.responseContentType = StringUtils.EMPTY;
    }

    public HttpResponse(HttpResponse httpResponse) {
        this.headers = new ConcurrentHashMap<>(httpResponse.getHeaders());
        this.responseBody = new StringBuilder(httpResponse.responseBody);
        this.responseContentType = new String(httpResponse.responseContentType.trim());
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public StringBuilder getResponseBody() {
        return this.responseBody;
    }

    public void setResponseBody(StringBuilder responseBody) {
        this.responseBody = responseBody;
    }

    public String getResponseContentType() {
        return responseContentType;
    }

    public void setResponseContentType(String responseContentType) {
        if (StringUtils.isNotBlank(responseContentType)) {
            this.responseContentType = StringUtils.substringBefore(responseContentType, ";").trim().toLowerCase();
        } else {
            this.responseContentType = StringUtils.EMPTY;
        }
    }

    public boolean isEmpty() {
        return StringUtils.isAnyBlank(responseBody, responseContentType);
    }
}
