package com.nr.agent.security.random.java.security;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.HashCryptoOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.security.MessageDigest;
import java.security.Provider;

import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.DEFAULT;
import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.LOW_SEVERITY_HOOKS_ENABLED;

@Weave(type = MatchType.ExactClass, originalName = "java.security.MessageDigest")
public class MessageDigest_Instrumentation {

    public static MessageDigest getInstance(String algorithm) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
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
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
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
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
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

    private static void registerExitOperation(AbstractOperation operation) {
        try {
            if (operation == null || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }
}
