package com.newrelic.agent.security.instrumentation.random.java.util;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RandomOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
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
        boolean isLockAcquired = false;
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            isLockAcquired = acquireLockIfPossible(hashCode());
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextInt");
        }
        int returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(isLockAcquired, operation);
            }
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        return returnValue;
    }

    public int nextInt(int bound) {
        boolean isLockAcquired = false;
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            isLockAcquired = acquireLockIfPossible(hashCode());
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextInt");
        }
        int returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(isLockAcquired, operation);
            }
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        return returnValue;
    }

    public void nextBytes(byte[] bytes) {
        boolean isLockAcquired = false;
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            isLockAcquired = acquireLockIfPossible(hashCode());
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextBytes");
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(isLockAcquired, operation);
            }
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
    }

    public long nextLong() {
        boolean isLockAcquired = false;
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            isLockAcquired = acquireLockIfPossible(hashCode());
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextLong");
        }
        long returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(isLockAcquired, operation);
            }
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        return returnValue;
    }

    public float nextFloat() {
        boolean isLockAcquired = false;
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            isLockAcquired = acquireLockIfPossible(hashCode());
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextFloat");
        }
        float returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(isLockAcquired, operation);
            }
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        return returnValue;
    }

    public double nextDouble() {
        boolean isLockAcquired = false;
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            isLockAcquired = acquireLockIfPossible(hashCode());
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextDouble");
        }
        double returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(isLockAcquired, operation);
            }
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        return returnValue;
    }

    public double nextGaussian() {
        boolean isLockAcquired = false;
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            isLockAcquired = acquireLockIfPossible(hashCode());
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextGaussian");
        }
        double returnValue = -1;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(isLockAcquired, operation);
            }
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        return returnValue;
    }

    public boolean nextBoolean() {
        boolean isLockAcquired = false;
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            isLockAcquired = acquireLockIfPossible(hashCode());
            if (isLockAcquired)
                operation = preprocessSecurityHook(getClass().getName(), "nextBoolean");
        }
        boolean returnValue;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(isLockAcquired, operation);
            }
            if (isLockAcquired) {
                releaseLock(hashCode());
            }
        }
        return returnValue;
    }

    private AbstractOperation preprocessSecurityHook(String className, String methodName) {
        try {
            RandomOperation operation = null;
            Object obj = this;
            if (obj instanceof SecureRandom) {
                operation = new RandomOperation(SECURE_RANDOM, className, methodName);
            } else {
                operation = new RandomOperation(WEAK_RANDOM, className, methodName);
            }
            operation.setLowSeverityHook(true);

            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(
                        LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, Random_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, Random_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, Random_Instrumentation.class.getName());
        }
        return null;
    }

    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerOperation(operation);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, Random_Instrumentation.class.getName());
        }
    }

    private void releaseLock(int hashCode) {
        GenericHelper.releaseLock(RandomUtils.NR_SEC_RANDOM_ATTRIB_NAME, hashCode);
    }

    private boolean acquireLockIfPossible(int hashCode) {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.RANDOM, RandomUtils.NR_SEC_RANDOM_ATTRIB_NAME, hashCode);
    }
}
