package com.newrelic.agent.security.instrumentation.spray.client;

public class SprayUtils {
    private static final String NR_SEC_OPERATION_LOCK = "OPERATION_LOCK_SPRAY_CAN_CLIENT-";
    public static final String METHOD_SEND_RECEIVE = "sendReceive";
    public static final String SPRAY_CLIENT = "SPRAY-CLIENT";
    public static String getNrSecCustomAttribName() {
        return NR_SEC_OPERATION_LOCK + Thread.currentThread().getId();
    }
}
