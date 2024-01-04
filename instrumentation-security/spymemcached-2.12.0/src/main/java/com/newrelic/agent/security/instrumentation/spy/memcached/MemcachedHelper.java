package com.newrelic.agent.security.instrumentation.spy.memcached;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.MemcachedOperation;
import net.spy.memcached.ops.CASOperation;
import net.spy.memcached.ops.ConcatenationOperation;
import net.spy.memcached.ops.Operation;
import net.spy.memcached.ops.StoreOperation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Arrays;

public class MemcachedHelper {
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "MEMCACHED_OPERATION_LOCK_";
    public static final String WRITE = "write";
    public static final String UPDATE = "update";
    public static final String METHOD_ASYNC_STORE = "asyncStore";
    public static final String METHOD_ASYNC_CAT = "asyncCat";
    public static final String METHOD_ASYNC_CAS = "asyncCAS";

    public static AbstractOperation preprocessSecurityHook(String command, String type, String key, Object val, String klass, String method) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()){
                return null;
            }
            MemcachedOperation operation = new MemcachedOperation(command, Arrays.asList(key, val), type, klass, method);
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
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
        } catch (Throwable ignored){}
    }
}
