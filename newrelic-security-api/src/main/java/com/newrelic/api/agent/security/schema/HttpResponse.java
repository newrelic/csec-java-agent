package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import com.newrelic.api.agent.security.StringBuilderLimit;

public class HttpResponse {

    private Map<String, String> headers;

    private final StringBuilderLimit body;

    private String contentType;

    private int statusCode;

    public HttpResponse() {
        this.headers = new ConcurrentHashMap<>();
        this.body = new StringBuilderLimit();
        this.contentType = StringUtils.EMPTY;
        body.setDataTruncated(false);
    }

    public HttpResponse(HttpResponse httpResponse) {
        this.headers = new ConcurrentHashMap<>(httpResponse.getHeaders());
        this.body = httpResponse.body;
        this.contentType = httpResponse.contentType.trim();
        this.statusCode = httpResponse.statusCode;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public StringBuilderLimit getBody() {
        return this.body;
    }

    public void setBody(StringBuilder body) {
        this.body.setSb(body);
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

    public boolean isEmpty() {
        return StringUtils.isAnyBlank(body.getSb(), contentType);
    }

    public void clean() {
        headers.clear();
        body.clean();
        contentType = StringUtils.EMPTY;
        statusCode = 0;
    }
}
