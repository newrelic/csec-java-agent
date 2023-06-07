package com.nr.instrumentation.security.grpc1220;

import com.google.protobuf.Descriptors;
import com.google.protobuf.MessageOrBuilder;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcHelper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GrpcUtils {
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "NR_CSEC_GRPC_OBJECT_LOCK_";

    public enum Type {
        REQUEST,
        RESPONSE
    }

    public static <T> void preProcessSecurityHook(T receivedMessage, Type type) {
        try {
            if(receivedMessage!=null){
                Map<String, Object> message = ProtoMessageToMap.convertibleMessageFormat((MessageOrBuilder) receivedMessage);
                StringBuilder jsonString;

                switch (type) {
                    case REQUEST:
                        jsonString = GrpcHelper.convertToJsonString(message, NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody());
                        NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().setBody(jsonString);
                        break;
                    case RESPONSE:
                        jsonString = GrpcHelper.convertToJsonString(message, NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody());
                        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseBody(jsonString);
                        break;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    public static void releaseLock(int hashcode) {
        try {
            try {
                if(NewRelicSecurity.isHookProcessingActive()) {
                    NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(NR_SEC_CUSTOM_ATTRIB_NAME+hashcode, null);
                }
            } catch (Throwable ignored){}
        } catch (Throwable ignored) {
        }
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
