package com.newrelic.agent.security.instrumentation.jcache_1_0_0;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.JCacheOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.List;

public class JCacheHelper {
    public static final String READ = "read";
    public static final String WRITE = "write";
    public static final String DELETE = "delete";
    public static final String UPDATE = "update";
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "JCACHE-OPERATION-LOCK-";
    public static final String JCACHE_1_0_0 = "JCACHE-1.0.0";

    public static AbstractOperation preprocessSecurityHook(String command, List<Object> args, String klass, String method) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()){
                return null;
            }
            JCacheOperation operation = new JCacheOperation(klass, method, command, args);
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JCACHE_1_0_0, e.getMessage()), e, JCacheHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JCACHE_1_0_0, e.getMessage()), e, JCacheHelper.class.getName());
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, JCACHE_1_0_0, e.getMessage()), e, JCacheHelper.class.getName());
                throw e;
            }
        }
        return null;
    }

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, JCACHE_1_0_0, ignored.getMessage()), ignored, JCacheHelper.class.getName());
        }
    }

    public static void releaseLock(int hashcode) {
        try {
            GenericHelper.releaseLock(NR_SEC_CUSTOM_ATTRIB_NAME, hashcode);
        } catch (Throwable ignored) {}
    }

    public static boolean acquireLockIfPossible(int hashcode) {
        try {
            return GenericHelper.acquireLockIfPossible(NR_SEC_CUSTOM_ATTRIB_NAME, hashcode);
        } catch (Throwable ignored) {}
        return false;
    }
}
