package com.newrelic.agent.security.introspec;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;

import java.sql.Statement;
import java.util.List;

public interface SecurityIntrospector {

    List<AbstractOperation> getOperations();

    String getJDBCVendor();

    String getSqlQuery(Statement statement);

    int getRequestReaderHash();

    int getRequestInStreamHash();

    int getResponseWriterHash();

    int getResponseOutStreamHash();

    SecurityMetaData getSecurityMetaData();

    void setResponseOutStreamHash(int hashCode);

    void setResponseWriterHash(int hashCode);

    void setRequestInputStreamHash(int hashCode);

    void setRequestReaderHash(int hashCode);

    void setK2FuzzRequestId(String value);

    void setK2TracingData(String value);

    void clear();
}