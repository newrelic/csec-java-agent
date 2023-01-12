package com.newrelic.agent.security.introspec;

import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.api.agent.security.schema.AbstractOperation;

import java.sql.Statement;
import java.util.List;

public interface SecurityIntrospector {

    List<AbstractOperation> getOperations();

    List<ExitEventBean> getExitEvents();

    String getJDBCVendor();

    String getSqlQuery(Statement statement);

    int getRequestHash();

    void clear();
}