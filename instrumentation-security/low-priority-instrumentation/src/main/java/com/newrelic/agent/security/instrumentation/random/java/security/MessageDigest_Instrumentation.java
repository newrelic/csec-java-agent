package com.newrelic.agent.security.instrumentation.random.java.security;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.HashCryptoOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.security.MessageDigest;
import java.security.Provider;

@Weave(type = MatchType.ExactClass, originalName = "java.security.MessageDigest")
public class MessageDigest_Instrumentation {

    public static MessageDigest getInstance(String algorithm) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            operation = preprocessSecurityHook(algorithm, StringUtils.EMPTY, MessageDigest.class.getName(), "getInstance");
        }
        MessageDigest returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(operation);
            }
        }
        return returnValue;
    }

    public static MessageDigest getInstance(String algorithm, String provider) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            operation = preprocessSecurityHook(algorithm, provider, MessageDigest.class.getName(), "getInstance");
        }
        MessageDigest returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(operation);
            }
        }
        return returnValue;
    }

    public static MessageDigest getInstance(String algorithm, Provider provider) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            operation = preprocessSecurityHook(algorithm, provider.getClass().getSimpleName(), MessageDigest.class.getName(), "getInstance");
        }
        MessageDigest returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(operation);
            }
        }
        return returnValue;
    }

    private static AbstractOperation preprocessSecurityHook(String algorithm, String provider, String className, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            HashCryptoOperation operation;
            operation = new HashCryptoOperation(algorithm, className, methodName);
            operation.setProvider(provider);
            operation.setLowSeverityHook(true);

            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(
                        LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, MessageDigest_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, MessageDigest_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, MessageDigest_Instrumentation.class.getName());
        }
        return null;
    }

    private static void registerExitOperation(AbstractOperation operation) {
        try {
            if (operation == null || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerOperation(operation);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, MessageDigest_Instrumentation.class.getName());
        }
    }
}
