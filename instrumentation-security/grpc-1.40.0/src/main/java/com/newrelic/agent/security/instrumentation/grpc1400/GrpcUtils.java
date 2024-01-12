package com.newrelic.agent.security.instrumentation.grpc1400;

import com.google.protobuf.MessageOrBuilder;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class GrpcUtils {
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "NR_CSEC_GRPC_OBJECT_LOCK_";

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
        } catch (Throwable ignored) {
        }
    }

    public static void releaseLock(int hashcode) {
        try {
            if(NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(NR_SEC_CUSTOM_ATTRIB_NAME+hashcode, null);
            }
        } catch (Throwable ignored){}
    }

    public static boolean acquireLockIfPossible(int hashcode) {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isLockAcquired(NR_SEC_CUSTOM_ATTRIB_NAME+hashcode)) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(NR_SEC_CUSTOM_ATTRIB_NAME+hashcode, true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    private static boolean isLockAcquired(String nrSecCustomAttrName) {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(nrSecCustomAttrName, Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }
}
