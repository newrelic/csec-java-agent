package com.newrelic.agent.security.instrumentation.random.java.util;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RandomOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.random.RandomUtils;

import java.security.SecureRandom;

import static com.newrelic.agent.security.instrumentation.random.RandomUtils.SECURE_RANDOM;
import static com.newrelic.agent.security.instrumentation.random.RandomUtils.WEAK_RANDOM;

@Weave(type = MatchType.BaseClass, originalName = "java.util.Random")
public class Random_Instrumentation {

    public int nextInt() {
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextInt");
        }
        int returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        if (isOwaspHookEnabled) {
            registerExitOperation(isLockAcquired, operation);
        }
        return returnValue;
    }

    public int nextInt(int bound) {
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextInt");
        }
        int returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        if (isOwaspHookEnabled) {
            registerExitOperation(isLockAcquired, operation);
        }
        return returnValue;
    }

    public void nextBytes(byte[] bytes) {
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextBytes");
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        if (isOwaspHookEnabled) {
            registerExitOperation(isLockAcquired, operation);
        }
    }

    public long nextLong() {
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextLong");
        }
        long returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        if (isOwaspHookEnabled) {
            registerExitOperation(isLockAcquired, operation);
        }
        return returnValue;
    }

    public float nextFloat() {
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextFloat");
        }
        float returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        if (isOwaspHookEnabled) {
            registerExitOperation(isLockAcquired, operation);
        }
        return returnValue;
    }

    public double nextDouble() {
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextDouble");
        }
        double returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        if (isOwaspHookEnabled) {
            registerExitOperation(isLockAcquired, operation);
        }
        return returnValue;
    }

    public double nextGaussian() {
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextGaussian");
        }
        double returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        if (isOwaspHookEnabled) {
            registerExitOperation(isLockAcquired, operation);
        }
        return returnValue;
    }

    public boolean nextBoolean() {
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextBoolean");
        }
        boolean returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        if (isOwaspHookEnabled) {
            registerExitOperation(isLockAcquired, operation);
        }
        return returnValue;
    }

    private AbstractOperation preprocessSecurityHook(String className, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            RandomOperation operation = null;
            Object obj = this;
            if (obj instanceof SecureRandom) {
                operation = new RandomOperation(SECURE_RANDOM, className, methodName);
            } else {
                operation = new RandomOperation(WEAK_RANDOM, className, methodName);
            }
            operation.setLowSeverityHook(true);

            NewRelicSecurity.getAgent().registerOperation(operation);

            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }

    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }

    private void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(RandomUtils.NR_SEC_RANDOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible(int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(RandomUtils.NR_SEC_RANDOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
        return false;
    }
}
