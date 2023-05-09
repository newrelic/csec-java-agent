package com.newrelic.agent.security.introspec;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.helper.Log4JStrSubstitutor;

import java.sql.Statement;
import java.util.List;
import java.util.Set;

public interface SecurityIntrospector {

    List<AbstractOperation> getOperations();

    String getJDBCVendor();

    String getR2DBCVendor();

    String getSqlQuery(Statement statement);

    Set getRequestReaderHash();

    Set getRequestInStreamHash();

    Set getResponseWriterHash();

    Set getResponseOutStreamHash();
    Log4JStrSubstitutor getLog4JStrSubstitutor();

    SecurityMetaData getSecurityMetaData();

    void setResponseOutStreamHash(int hashCode);

    void setResponseWriterHash(int hashCode);

    void setRequestInputStreamHash(int hashCode);

    void setRequestReaderHash(int hashCode);

    void setK2FuzzRequestId(String value);

    void setK2TracingData(String value);

    void clear();
}