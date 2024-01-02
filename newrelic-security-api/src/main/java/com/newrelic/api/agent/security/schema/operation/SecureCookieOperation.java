package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class SecureCookieOperation extends AbstractOperation {
    private String value;

    private boolean isSecure;
    private boolean isHttpOnly;
    private boolean isSameSiteStrict;

    private String cookie;

    public SecureCookieOperation(String value, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.SECURE_COOKIE);
        this.value = value;
    }

    public SecureCookieOperation(String value, boolean isSecure, boolean isHttpOnly, boolean isSameSiteStrict, String cookie, String className, String methodName) {
        this(value, className, methodName);
        this.isSecure = isSecure;
        this.isHttpOnly = isHttpOnly;
        this.isSameSiteStrict = isSameSiteStrict;
        this.cookie = cookie;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public boolean isSecure() {
        return isSecure;
    }

    public void setSecure(boolean secure) {
        isSecure = secure;
    }

    public boolean isHttpOnly() {
        return isHttpOnly;
    }

    public void setHttpOnly(boolean httpOnly) {
        isHttpOnly = httpOnly;
    }

    public boolean isSameSiteStrict() {
        return isSameSiteStrict;
    }

    public void setSameSiteStrict(boolean sameSiteStrict) {
        isSameSiteStrict = sameSiteStrict;
    }

    public String getCookie() {
        return cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    @Override
    public boolean isEmpty() {
        return (value == null || value.trim().isEmpty());
    }

}
