package com.newrelic.api.agent.security.schema.policy;

import java.util.List;

public class AccountInfo {

    private final List<String> accountIds;

    public AccountInfo() {
        this.accountIds = null;
    }

    public AccountInfo(List<String> accountIds) {
        this.accountIds = accountIds;
    }

    public List<String> getAccountIds() {
        return accountIds;
    }

    public boolean isEmpty() {
        if(accountIds == null) {
            return true;
        }
        return accountIds.isEmpty();
    }
}
