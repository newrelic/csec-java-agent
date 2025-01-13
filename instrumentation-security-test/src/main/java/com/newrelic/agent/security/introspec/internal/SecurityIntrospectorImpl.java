package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.helper.Log4JStrSubstitutor;
import com.newrelic.api.agent.security.utils.UserDataTranslationHelper;

import java.io.IOException;
import java.net.ServerSocket;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

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
    public String getR2DBCVendor() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, String.class);

    }

    @Override
    public String getSqlQuery(Statement statement) {
        return JdbcHelper.getSql(statement);
    }

    @Override
    public Set getResponseWriterHash() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_WRITER_HASH, Set.class);
    }

    @Override
    public Set getRequestReaderHash() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_READER_HASH, Set.class);
    }

    @Override
    public Set getRequestInStreamHash() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_INPUTSTREAM_HASH, Set.class);
    }

    @Override
    public Set getResponseOutStreamHash() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, Set.class);
    }

    @Override
    public Log4JStrSubstitutor getLog4JStrSubstitutor() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(
                UserDataTranslationHelper.getAttributeName(Log4JStrSubstitutor.class.getName()),
                Log4JStrSubstitutor.class
        );
    }

    @Override
    public SecurityMetaData getSecurityMetaData() {
        return NewRelicSecurity.getAgent().getSecurityMetaData();
    }

    @Override
    public void setResponseOutStreamHash(int hashCode) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, Collections.singleton(hashCode));
    }

    @Override
    public void setResponseWriterHash(int hashCode) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_WRITER_HASH, Collections.singleton(hashCode));
    }

    @Override
    public void setRequestReaderHash(int hashCode) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_READER_HASH, Collections.singleton(hashCode));
    }

    @Override
    public void setK2FuzzRequestId(String value) {
        K2RequestIdentifier k2RequestIdentifierInstance = new K2RequestIdentifier();
        k2RequestIdentifierInstance.setRaw(value);
        NewRelicSecurity.getAgent().getSecurityMetaData().setFuzzRequestIdentifier(k2RequestIdentifierInstance);
    }

    @Override
    public void setK2TracingData(String value) {
        NewRelicSecurity.getAgent().getSecurityMetaData().setTracingHeaderValue(value);
    }

    @Override
    public List<?> getGRPCRequest() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA, List.class);
    }

    @Override
    public List<?> getGRPCResponse() {
        return NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GrpcHelper.NR_SEC_GRPC_RESPONSE_DATA, List.class);
    }

    @Override
    public void setK2ParentId(String value) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(GenericHelper.CSEC_PARENT_ID, value);
    }

    @Override
    public void setRequestInputStreamHash(int hashCode) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_INPUTSTREAM_HASH, Collections.singleton(hashCode));
    }

    @Override
    public void clear() {
        NewRelicSecurity.getAgent().getSecurityMetaData().clearCustomAttr();
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(Agent.OPERATIONS, new ArrayList<>());
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(Agent.EXIT_OPERATIONS, new ArrayList<>());

        SecurityMetaData meta = NewRelicSecurity.getAgent().getSecurityMetaData();
        meta.setRequest(new HttpRequest());
        meta.setResponse(new HttpResponse());
        meta.getRequest().setUrl("/TestUrl");
        meta.getRequest().setMethod("GET");
    }

    @Override
    public int getRandomPort() {
        int port;
        try {
            ServerSocket socket = new ServerSocket(0);
            port = socket.getLocalPort();
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port");
        }
        return port;
    }
}