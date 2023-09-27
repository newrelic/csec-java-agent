package net.spy.memcached;

import com.newrelic.agent.security.instrumentation.spy.memcached.MemcachedHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.MemcachedOperation;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import net.spy.memcached.internal.OperationFuture;
import net.spy.memcached.ops.ConcatenationType;
import net.spy.memcached.ops.Operation;
import net.spy.memcached.ops.StoreType;
import net.spy.memcached.transcoders.Transcoder;

@Weave(originalName = "net.spy.memcached.MemcachedClient")
public class MemcachedClient_Instrumentation {
    private <T> OperationFuture<Boolean> asyncStore(StoreType storeType,
                String key, int exp, T value, Transcoder<T> tc) {
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(MemcachedHelper.NR_SEC_CUSTOM_ATTRIB_NAME, value.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = MemcachedHelper.preprocessSecurityHook(key, value, this.getClass().getName(), "asyncStore");
        }
        OperationFuture<Boolean> returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                GenericHelper.releaseLock(MemcachedHelper.NR_SEC_CUSTOM_ATTRIB_NAME, value.hashCode());
            }
        }
        MemcachedHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    private <T> OperationFuture<Boolean> asyncCat(ConcatenationType catType,
            long cas, String key, T value, Transcoder<T> tc) {
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(MemcachedHelper.NR_SEC_CUSTOM_ATTRIB_NAME, value.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = MemcachedHelper.preprocessSecurityHook(key, value, this.getClass().getName(), "asyncCat");
        }
        OperationFuture<Boolean> returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                GenericHelper.releaseLock(MemcachedHelper.NR_SEC_CUSTOM_ATTRIB_NAME, value.hashCode());
            }
        }
        MemcachedHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public <T> OperationFuture<CASResponse>
    asyncCAS(String key, long casId, int exp, T value, Transcoder<T> tc) {
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(MemcachedHelper.NR_SEC_CUSTOM_ATTRIB_NAME, value.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = MemcachedHelper.preprocessSecurityHook(key, value, this.getClass().getName(), "asyncCAS");
        }
        OperationFuture<CASResponse> returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                GenericHelper.releaseLock(MemcachedHelper.NR_SEC_CUSTOM_ATTRIB_NAME, value.hashCode());
            }
        }
        MemcachedHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }
}
