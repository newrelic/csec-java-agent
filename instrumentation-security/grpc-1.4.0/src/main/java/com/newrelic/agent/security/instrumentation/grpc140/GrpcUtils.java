package com.newrelic.agent.security.instrumentation.grpc140;

import com.google.protobuf.MessageOrBuilder;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class GrpcUtils {
    private static final String NR_SEC_CUSTOM_ATTRIB_NAME = "NR_CSEC_GRPC_OBJECT_LOCK_";
    public static final String GRPC_1_4_0 = "GRPC-1.4.0";

    public enum Type {
        REQUEST,
        RESPONSE
    }

    public static <T> void preProcessSecurityHook(T receivedMessage, Type type, String dataType) {
        try {
            if(receivedMessage!=null){
                Map<String, Object> message = ProtoMessageToMap.convertibleMessageFormat((MessageOrBuilder) receivedMessage);

                switch (type) {
                    case REQUEST:
                        if(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA, List.class)==null){
                            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA, new ArrayList());
                        }
                        NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA, List.class).add(message);
                        NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().addReflectedMetaData(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA_TYPE, dataType);
                        break;
                    case RESPONSE:
                        if(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GrpcHelper.NR_SEC_GRPC_RESPONSE_DATA, List.class)==null){
                            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(GrpcHelper.NR_SEC_GRPC_RESPONSE_DATA, new ArrayList());
                        }
                        NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GrpcHelper.NR_SEC_GRPC_RESPONSE_DATA, List.class).add(message);
                        NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().addReflectedMetaData(GrpcHelper.NR_SEC_GRPC_RESPONSE_DATA_TYPE, dataType);
                        break;
                }
            }
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(
                    LogLevel.WARNING, String.format(GenericHelper.ERROR_PARSING_HTTP_REQUEST_DATA, GRPC_1_4_0, e.getMessage()), e, GrpcUtils.class.getName());
        }
    }

    public static void releaseLock(int hashcode) {
        GenericHelper.releaseLock(NR_SEC_CUSTOM_ATTRIB_NAME, hashcode);
    }

    public static boolean acquireLockIfPossible(int hashcode) {
        return GenericHelper.acquireLockIfPossible(NR_SEC_CUSTOM_ATTRIB_NAME, hashcode);
    }
}
