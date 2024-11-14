package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class HttpResponse {

    @JsonIgnore
    public static final int MAX_ALLOWED_RESPONSE_BODY_LENGTH = 500000;

    private Map<String, String> headers;

    private StringBuilder body;

    private String contentType;

    private int statusCode;

    private boolean dataTruncated;

    public HttpResponse() {
        this.headers = new ConcurrentHashMap<>();
        this.body = new StringBuilder();
        this.contentType = StringUtils.EMPTY;
        this.dataTruncated = false;
    }

    public HttpResponse(HttpResponse httpResponse) {
        this.headers = new ConcurrentHashMap<>(httpResponse.getHeaders());
        this.body = new StringBuilder(httpResponse.body);
        this.contentType = httpResponse.contentType.trim();
        this.statusCode = httpResponse.statusCode;
        this.dataTruncated = httpResponse.dataTruncated;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public StringBuilder getBody() {
        return this.body;
    }

    public void setBody(StringBuilder body) {
        this.body = body;
    }

    public String getResponseContentType() {
        return contentType;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String responseContentType) {
        if (StringUtils.isNotBlank(responseContentType)) {
            this.contentType = StringUtils.substringBefore(responseContentType, ";").trim().toLowerCase();
        } else {
            this.contentType = StringUtils.EMPTY;
        }
    }

    public boolean isDataTruncated() {
        return dataTruncated;
    }

    public void setDataTruncated(boolean dataTruncated) {
        this.dataTruncated = dataTruncated;
    }

    public boolean isEmpty() {
        return StringUtils.isAnyBlank(body, contentType);
    }
}
