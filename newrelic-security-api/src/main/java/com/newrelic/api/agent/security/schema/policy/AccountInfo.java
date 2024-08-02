package com.newrelic.api.agent.security.schema.policy;

public class AccountInfo {

    private final String accountId;

    public AccountInfo() {
        this.accountId = null;
    }

    public AccountInfo(String accountId) {
        this.accountId = accountId;
    }

    public String getAccountId() {
        return accountId;
    }
}
