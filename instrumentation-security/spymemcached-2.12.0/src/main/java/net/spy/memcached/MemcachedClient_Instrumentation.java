package net.spy.memcached;

import com.newrelic.agent.security.instrumentation.spy.memcached.MemcachedHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import net.spy.memcached.internal.OperationFuture;
import net.spy.memcached.ops.ConcatenationType;
import net.spy.memcached.ops.StoreType;
import net.spy.memcached.transcoders.Transcoder;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;

@Weave(originalName = "net.spy.memcached.MemcachedClient")
public class MemcachedClient_Instrumentation {

    public MemcachedClient_Instrumentation(ConnectionFactory cf, List<InetSocketAddress> addrs) throws IOException {
        try {
            if (addrs != null) {
                for (InetSocketAddress address : addrs) {
                    NewRelicSecurity.getAgent().recordExternalConnection(address.getHostName(), address.getPort(), null, address.getAddress().getHostAddress(),
                                    ExternalConnectionType.DATABASE_CONNECTION.name(), MemcachedHelper.SPYMEMCACHED_2_12_0);
                }
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_DETECTING_CONNECTION_STATS, MemcachedHelper.SPYMEMCACHED_2_12_0, e.getMessage()), this.getClass().getName());
        }
    }

    private <T> OperationFuture<Boolean> asyncStore(StoreType storeType,
                String key, int exp, T value, Transcoder<T> tc) {
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(MemcachedHelper.NR_SEC_CUSTOM_ATTRIB_NAME, value.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = MemcachedHelper.preprocessSecurityHook(storeType.name(), MemcachedHelper.WRITE, key, value, this.getClass().getName(), MemcachedHelper.METHOD_ASYNC_STORE);
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
            operation = MemcachedHelper.preprocessSecurityHook(catType.name(), MemcachedHelper.UPDATE, key, value, this.getClass().getName(), MemcachedHelper.METHOD_ASYNC_CAT);
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
            operation = MemcachedHelper.preprocessSecurityHook(StoreType.set.name(), MemcachedHelper.WRITE, key, value, this.getClass().getName(), MemcachedHelper.METHOD_ASYNC_CAS);
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
