package com.newrelic.api.agent.security.schema;

import java.util.Objects;

public class ApplicationURLMapping {
    private String method;
    private String url;
    private String handler;

    public ApplicationURLMapping(String method, String url) {
        this.method = method;
        this.url = url;
    }

    public ApplicationURLMapping(String method, String url, String handler) {
        this.method = method;
        this.url = url;
        this.handler = handler;
    }

    public String getHandler() {
        return handler;
    }

    public void setHandler(String handler) {
        this.handler = handler;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj instanceof ApplicationURLMapping) {
            ApplicationURLMapping mapping = (ApplicationURLMapping) obj;
            return url.equals(mapping.url) && method.equals(mapping.method) && handler.equals(mapping.handler);
        }
        return false;
    }

    @Override
    public String toString() {
        return String.format("Method: %s, Url: %s, Handler: %s", method, url, handler);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, url, handler);
    }
}
