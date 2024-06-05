package com.newrelic.api.agent.security.schema;

import java.util.Objects;

public class ApplicationURLMapping {
    private String method;
    private String path;
    private String handler;

    public ApplicationURLMapping(String method, String url) {
        this(method, url, null);
    }

    public ApplicationURLMapping(String method, String url, String handler) {
        this.method = method;
        this.path = StringUtils.removeEnd(StringUtils.prependIfMissing(url, StringUtils.SEPARATOR), StringUtils.SEPARATOR);
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

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = StringUtils.removeEnd(StringUtils.prependIfMissing(path, StringUtils.SEPARATOR), StringUtils.SEPARATOR);;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof ApplicationURLMapping) {
            ApplicationURLMapping mapping = (ApplicationURLMapping) obj;
            return Objects.equals(this.path, mapping.path) &&
                    Objects.equals(this.method, mapping.method) &&
                    Objects.equals(this.handler, mapping.handler);
        }
        return false;
    }

    @Override
    public String toString() {
        return String.format("Method: %s, Url: %s, Handler: %s", method, path, handler);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, path, handler);
    }
}
