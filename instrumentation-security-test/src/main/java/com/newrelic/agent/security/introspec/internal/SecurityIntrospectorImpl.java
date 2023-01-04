package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.JDBCVendor;

import java.sql.Statement;
import java.util.List;

public class SecurityIntrospectorImpl implements SecurityIntrospector {
    @Override
    public List<AbstractOperation> getOperations() {
        return (List<AbstractOperation>) NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.OPERATIONS, List.class);
    }

    @Override
    public List<ExitEventBean> getExitEvents() {
        return (List<ExitEventBean>) NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.EXIT_OPERATIONS, List.class);
    }

    @Override
    public String getJDBCVendor() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, String.class);
    }

    @Override
    public String getSqlQuery(Statement statement) {
        return JdbcHelper.getSql(statement);
    }

    @Override
    public void clear() {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, null);
        NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.OPERATIONS, List.class).clear();
        NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.EXIT_OPERATIONS, List.class).clear();
    }
}