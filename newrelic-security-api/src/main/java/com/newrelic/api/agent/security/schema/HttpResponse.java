package com.newrelic.api.agent.security.schema;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class HttpResponse {

    private Map<String, String> headers;

    private StringBuilder responseBody;

    private String contentType;

    private int responseCode;

    public HttpResponse() {
        this.headers = new ConcurrentHashMap<>();
        this.responseBody = new StringBuilder();
        this.contentType = StringUtils.EMPTY;
    }

    public HttpResponse(HttpResponse httpResponse) {
        this.headers = new ConcurrentHashMap<>(httpResponse.getHeaders());
        this.responseBody = new StringBuilder(httpResponse.responseBody);
        this.contentType = new String(httpResponse.contentType.trim());
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
        return contentType;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public void setResponseContentType(String responseContentType) {
        if (StringUtils.isNotBlank(responseContentType)) {
            this.contentType = StringUtils.substringBefore(responseContentType, ";").trim().toLowerCase();
        } else {
            this.contentType = StringUtils.EMPTY;
        }
    }

    public boolean isEmpty() {
        return StringUtils.isAnyBlank(responseBody, contentType);
    }
}
