package javax.cache;

import com.newrelic.agent.security.instrumentation.jcache_1_0_0.JCacheHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import javax.cache.integration.CompletionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Weave(type = MatchType.Interface, originalName = "javax.cache.Cache")
public abstract class Cache_Instrumentation<K, V> {
    public V get(K key) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.READ, Collections.singletonList(key), this.getClass().getName(), "get");
        }
        V returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public Map<K, V> getAll(Set<? extends K> keys) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.READ, new ArrayList<Object>() { { addAll(keys); } }, this.getClass().getName(), "getAll");
        }
        Map<K, V> returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public boolean containsKey(K key) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.READ, Collections.singletonList(key), this.getClass().getName(), "containsKey");
        }
        boolean returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public void loadAll(Set<? extends K> keys, boolean replaceExistingValues, CompletionListener completionListener) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.READ, new ArrayList<Object>() { { addAll(keys); } }, this.getClass().getName(), "loadAll");
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
    }

    public void put(K key, V value) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.WRITE, Arrays.asList(key, value), this.getClass().getName(), "put");
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
    }

    public V getAndPut(K key, V value) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.WRITE, Arrays.asList(key, value), this.getClass().getName(), "getAndPut");
        }
        V returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public void putAll(Map<? extends K, ? extends V> map) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            List<Object> argList = new ArrayList<>();
            for (Map.Entry<? extends K, ? extends V> entry : map.entrySet()) {
                argList.add(entry.getKey());
                argList.add(entry.getValue());
            }
            // do not call register exit operation method, this will lead to a verify error
            // Type 'java/lang/Object' (current frame, stack[0]) is not assignable to 'com/newrelic/api/agent/security/schema/AbstractOperation'
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.WRITE, argList, this.getClass().getName(), "putAll");
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
    }

    public boolean putIfAbsent(K key, V value) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.WRITE, Arrays.asList(key, value), this.getClass().getName(), "putIfAbsent");
        }
        boolean returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public boolean remove(K key) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.DELETE, Collections.singletonList(key), this.getClass().getName(), "remove");
        }
        boolean returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public boolean remove(K key, V oldValue) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.DELETE, Arrays.asList(key, oldValue), this.getClass().getName(), "remove");
        }
        boolean returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public V getAndRemove(K key) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.DELETE, Collections.singletonList(key), this.getClass().getName(), "getAndRemove");
        }
        V returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public boolean replace(K key, V oldValue) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.UPDATE, Arrays.asList(key, oldValue), this.getClass().getName(), "replace");
        }
        boolean returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public boolean replace(K key, V oldValue, V newValue) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.UPDATE, Arrays.asList(key, oldValue, newValue), this.getClass().getName(), "replace");
        }
        boolean returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public V getAndReplace(K key, V value) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.UPDATE, Arrays.asList(key, value), this.getClass().getName(), "getAndReplace");
        }
        V returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }

    public void removeAll(Set<? extends K> keys) {
        boolean isLockAcquired = JCacheHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = JCacheHelper.preprocessSecurityHook(JCacheHelper.DELETE, new ArrayList<Object>() { { addAll(keys); } }, this.getClass().getName(), "removeAll");
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                JCacheHelper.releaseLock(this.hashCode());
            }
        }
        JCacheHelper.registerExitOperation(isLockAcquired, operation);
    }
}
