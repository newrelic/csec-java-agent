package com.newrelic.agent.security.instrumentation.spy.memcached;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.MemcachedOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.Arrays;

public class MemcachedHelper {
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "MEMCACHED_OPERATION_LOCK_";
    public static final String WRITE = "write";
    public static final String UPDATE = "update";
    public static final String METHOD_ASYNC_STORE = "asyncStore";
    public static final String METHOD_ASYNC_CAT = "asyncCat";
    public static final String METHOD_ASYNC_CAS = "asyncCAS";
    private static final String SPYMEMCACHED_2_12_0 = "SPYMEMCACHED-2.12.0";

    public static AbstractOperation preprocessSecurityHook(String type, String command, String key, Object val, String klass, String method) {
        try {
            MemcachedOperation operation = new MemcachedOperation(command, Arrays.asList(key, val), type, klass, method);
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, SPYMEMCACHED_2_12_0, e.getMessage()), e, MemcachedHelper.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SPYMEMCACHED_2_12_0, e.getMessage()), e, MemcachedHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SPYMEMCACHED_2_12_0, e.getMessage()), e, MemcachedHelper.class.getName());
        }
        return null;
    }

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, SPYMEMCACHED_2_12_0, e.getMessage()), e, MemcachedHelper.class.getName());
        }
    }
}
