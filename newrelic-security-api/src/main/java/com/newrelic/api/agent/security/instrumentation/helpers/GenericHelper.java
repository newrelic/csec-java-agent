package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;

import java.util.regex.Pattern;

public class GenericHelper {
    public static Pattern QUOTED_STRING_PATTERN = Pattern.compile("((\\\\)*?('|\\\"))(([\\s\\S]*?)(?:(?=(\\\\?))\\6.)*?)\\1",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    public static Pattern STORED_PROCEDURE_PATTERN = Pattern.compile("(call\\s+[a-zA-Z0-9_\\$]+\\(.*?\\))",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    public static final String CSEC_PARENT_ID = "nr-csec-parent-id";
    public static final String NR_SEC_CUSTOM_SPRING_REDIS_ATTR = "SPRING-DATA-REDIS";

    public static final String REGISTER_OPERATION_EXCEPTION_MESSAGE = "Instrumentation library: %s , error while library instrumented call processing : %s";
    public static final String EXIT_OPERATION_EXCEPTION_MESSAGE = "Instrumentation library: %s , error while generating exit operation: %s";
    public static final String SECURITY_EXCEPTION_MESSAGE = "New Relic Security Exception raised for Instrumentation library: %s, reason: %s ";
    public static final String URI_EXCEPTION_MESSAGE = "Instrumentation library: %s , error while extracting URI : %s";
    public static final String ERROR_GENERATING_HTTP_REQUEST = "Instrumentation library: %s , error while generating HTTP request : %s";
    public static final String ERROR_PARSING_HTTP_REQUEST_DATA = "Instrumentation library: %s , error while parsing HTTP request data : %s";
    public static final String ERROR_WHILE_GETTING_APP_ENDPOINTS = "Instrumentation library: %s , error while getting application API endpoints : %s";
    public static final String ERROR_PARSING_HTTP_RESPONSE = "Instrumentation library: %s , error while parsing HTTP Response data : %s";
    public static final String ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST = "Instrumentation library: %s , error while getting route for incoming request : %s";

    public static boolean skipExistsEvent() {
        if (!(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled() &&
                NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled())) {
            return true;
        }

        return false;
    }

    private static String getNrSecCustomAttribName(String nrSecCustomAttrName, int hashCode) {
        return nrSecCustomAttrName + Thread.currentThread().getId() + hashCode;
    }

    public static boolean isLockAcquired(String nrSecCustomAttrName) {
        return isLockAcquired(nrSecCustomAttrName, 0);
    }

    public static boolean isLockAcquired(String nrSecCustomAttrName, int hashCode) {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getNrSecCustomAttribName(nrSecCustomAttrName, hashCode), Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean acquireLockIfPossible(String nrSecCustomAttrName, int hashCode) {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isLockAcquired(nrSecCustomAttrName, hashCode)) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(nrSecCustomAttrName, hashCode), true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    public static void releaseLock(String nrSecCustomAttrName, int hashCode) {
        try {
            if(NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(nrSecCustomAttrName, hashCode), null);
            }
        } catch (Throwable ignored){}
    }

    public static boolean acquireLockIfPossible(String nrSecCustomAttrName) {
        return acquireLockIfPossible(nrSecCustomAttrName, 0);
    }

    public static void releaseLock(String nrSecCustomAttrName) {
        releaseLock(nrSecCustomAttrName, 0);
    }
}
