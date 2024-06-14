package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class SecureCookieOperationSet extends AbstractOperation {

    private Set<SecureCookieOperation> operations;

    public class SecureCookieOperation {
        private String name;
        private String value;

        private boolean isSecure;
        private boolean isHttpOnly;
        private boolean isSameSiteStrict;

        public SecureCookieOperation(String name, String value, boolean isSecure, boolean isHttpOnly, boolean isSameSiteStrict) {
            this.name = name;
            this.value = value;
            this.isSecure = isSecure;
            this.isHttpOnly = isHttpOnly;
            this.isSameSiteStrict = isSameSiteStrict;
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

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public boolean isEmpty() {
            return (value == null || value.trim().isEmpty());
        }
    }

    public SecureCookieOperationSet(String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.SECURE_COOKIE);
        this.operations = ConcurrentHashMap.newKeySet();
    }

    public void addOperation(String name, String value, boolean isSecure, boolean isHttpOnly, boolean isSameSiteStrict){
        this.operations.add(new SecureCookieOperation(name, value, isSecure, isHttpOnly, isSameSiteStrict));
    }

    public Set<SecureCookieOperation> getOperations() {
        return operations;
    }

    public void setOperations(Set<SecureCookieOperation> operations) {
        this.operations = operations;
    }

    @Override
    public boolean isEmpty() {
        return (operations == null || operations.isEmpty());
    }

}
