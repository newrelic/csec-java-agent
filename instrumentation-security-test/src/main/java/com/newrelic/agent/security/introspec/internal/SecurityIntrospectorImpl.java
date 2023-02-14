package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.schema.SecurityMetaData;

import java.sql.Statement;
import java.util.List;

public class SecurityIntrospectorImpl implements SecurityIntrospector {
    private static final String RESPONSE_WRITER_HASH = "RESPONSE_WRITER_HASH";
    private static final String RESPONSE_OUTPUTSTREAM_HASH = "RESPONSE_OUTPUTSTREAM_HASH";
    private static final String REQUEST_READER_HASH = "REQUEST_READER_HASH";
    private static final String REQUEST_INPUTSTREAM_HASH = "REQUEST_INPUTSTREAM_HASH";
    private static final String REQUEST_STREAM_OR_READER_CALLED = "REQUEST_STREAM_OR_READER_CALLED";
    private static final String RESPONSE_STREAM_OR_WRITER_CALLED = "RESPONSE_STREAM_OR_WRITER_CALLED";

    @Override
    public List<AbstractOperation> getOperations() {
        return (List<AbstractOperation>) NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.OPERATIONS, List.class);
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
    public int getResponseWriterHash() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_WRITER_HASH, Integer.class);
    }

    @Override
    public int getRequestReaderHash() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_READER_HASH, Integer.class);
    }

    @Override
    public int getResponseOutStreamHash() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, Integer.class);
    }

    @Override
    public SecurityMetaData getSecurityMetaData() {
        return NewRelicSecurity.getAgent().getSecurityMetaData();
    }

    @Override
    public int getRequestInStreamHash() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_INPUTSTREAM_HASH, Integer.class);
    }

    @Override
    public void setResponseOutStreamHash(int hashCode) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, hashCode);
    }

    @Override
    public void setResponseWriterHash(int hashCode) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_WRITER_HASH, hashCode);
    }

    @Override
    public void setRequestReaderHash(int hashCode) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_READER_HASH, hashCode);
    }

    @Override
    public void setRequestInputStreamHash(int hashCode) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_INPUTSTREAM_HASH, hashCode);
    }

    @Override
    public void clear() {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, null);
        NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.OPERATIONS, List.class).clear();
        NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.EXIT_OPERATIONS, List.class).clear();
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_READER_HASH, null);
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_INPUTSTREAM_HASH, null);
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_WRITER_HASH, null);
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, null);

        // used internally by some methods before saving hash code hence cleanup required
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_STREAM_OR_READER_CALLED, null);
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_STREAM_OR_WRITER_CALLED, null);

        SecurityMetaData meta = NewRelicSecurity.getAgent().getSecurityMetaData();
        meta.setRequest(new HttpRequest());
        meta.setResponse(new HttpResponse());
        meta.getRequest().setUrl("/TestUrl");
        meta.getRequest().setMethod("GET");
    }
}