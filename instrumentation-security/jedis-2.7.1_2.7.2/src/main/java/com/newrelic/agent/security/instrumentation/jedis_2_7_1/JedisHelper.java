package com.newrelic.agent.security.instrumentation.jedis_2_7_1;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RedisOperation;

import java.util.List;

public class JedisHelper {
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "REDIS_SERIALISED_DATA_";
    public static final String NR_SEC_LOCK_ATTRIB_NAME = "REDIS_SERIALISED_DATA_";
    public static AbstractOperation preprocessSecurityHook(String command, List<Object> args, String klass, String method) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()){
                return null;
            }
            RedisOperation operation = new RedisOperation(klass, method, command, args);
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

    public static void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(NR_SEC_LOCK_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {}
    }

    public static boolean acquireLockIfPossible(VulnerabilityCaseType cachingDataStore, int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(cachingDataStore, NR_SEC_LOCK_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {}
        return false;
    }
}
