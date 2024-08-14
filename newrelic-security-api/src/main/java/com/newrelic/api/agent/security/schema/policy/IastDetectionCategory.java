package com.newrelic.api.agent.security.schema.policy;

import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class IastDetectionCategory {

    public static final String STR_COMMA = ",";
    Boolean sqlInjectionEnabled = true;
    Boolean insecureSettingsEnabled = true;
    Boolean invalidFileAccessEnabled = true;
    Boolean noSqlInjectionEnabled = true;
    Boolean rxssEnabled = true;
    Boolean commandInjectionEnabled = true;
    Boolean ldapInjectionEnabled = true;
    Boolean javascriptInjectionEnabled = true;
    Boolean xpathInjectionEnabled = true;
    Boolean ssrfEnabled = true;

    private String disabledCategoriesCSV;

    public IastDetectionCategory() {
    }

    public Boolean getSqlInjectionEnabled() {
        return sqlInjectionEnabled;
    }

    public void setSqlInjectionEnabled(Boolean sqlInjectionEnabled) {
        this.sqlInjectionEnabled = sqlInjectionEnabled;
    }

    public Boolean getInsecureSettingsEnabled() {
        return insecureSettingsEnabled;
    }

    public void setInsecureSettingsEnabled(Boolean insecureSettingsEnabled) {
        this.insecureSettingsEnabled = insecureSettingsEnabled;
    }

    public Boolean getInvalidFileAccessEnabled() {
        return invalidFileAccessEnabled;
    }

    public void setInvalidFileAccessEnabled(Boolean invalidFileAccessEnabled) {
        this.invalidFileAccessEnabled = invalidFileAccessEnabled;
    }

    public Boolean getNoSqlInjectionEnabled() {
        return noSqlInjectionEnabled;
    }

    public void setNoSqlInjectionEnabled(Boolean noSqlInjectionEnabled) {
        this.noSqlInjectionEnabled = noSqlInjectionEnabled;
    }

    public Boolean getRxssEnabled() {
        return rxssEnabled;
    }

    public void setRxssEnabled(Boolean rxssEnabled) {
        this.rxssEnabled = rxssEnabled;
    }

    public Boolean getCommandInjectionEnabled() {
        return commandInjectionEnabled;
    }

    public void setCommandInjectionEnabled(Boolean commandInjectionEnabled) {
        this.commandInjectionEnabled = commandInjectionEnabled;
    }

    public Boolean getLdapInjectionEnabled() {
        return ldapInjectionEnabled;
    }

    public void setLdapInjectionEnabled(Boolean ldapInjectionEnabled) {
        this.ldapInjectionEnabled = ldapInjectionEnabled;
    }

    public Boolean getJavascriptInjectionEnabled() {
        return javascriptInjectionEnabled;
    }

    public void setJavascriptInjectionEnabled(Boolean javascriptInjectionEnabled) {
        this.javascriptInjectionEnabled = javascriptInjectionEnabled;
    }

    public Boolean getXpathInjectionEnabled() {
        return xpathInjectionEnabled;
    }

    public void setXpathInjectionEnabled(Boolean xpathInjectionEnabled) {
        this.xpathInjectionEnabled = xpathInjectionEnabled;
    }

    public Boolean getSsrfEnabled() {
        return ssrfEnabled;
    }

    public void setSsrfEnabled(Boolean ssrfEnabled) {
        this.ssrfEnabled = ssrfEnabled;
    }

    public void generateDisabledCategoriesCSV() {
        StringBuilder disabledCategoriesCSVBuilder = new StringBuilder();
        if (sqlInjectionEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.SQL_DB_COMMAND);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (insecureSettingsEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.HASH);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.RANDOM);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.SECURE_COOKIE);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.TRUSTBOUNDARY);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.CRYPTO);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (invalidFileAccessEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.FILE_INTEGRITY);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.FILE_OPERATION);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (noSqlInjectionEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.NOSQL_DB_COMMAND);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (rxssEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.REFLECTED_XSS);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (commandInjectionEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.SYSTEM_COMMAND);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (ldapInjectionEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.LDAP);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (javascriptInjectionEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.JAVASCRIPT_INJECTION);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (xpathInjectionEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.XPATH);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.XQUERY_INJECTION);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (ssrfEnabled) {
            disabledCategoriesCSVBuilder.append(VulnerabilityCaseType.HTTP_REQUEST);
            disabledCategoriesCSVBuilder.append(STR_COMMA);
        }
        if (disabledCategoriesCSVBuilder.length() > 0) {
            disabledCategoriesCSVBuilder.deleteCharAt(disabledCategoriesCSVBuilder.length() - 1);
        }
        disabledCategoriesCSV = disabledCategoriesCSVBuilder.toString();
    }

    public String getDisabledCategoriesCSV() {
        return disabledCategoriesCSV;
    }
}
