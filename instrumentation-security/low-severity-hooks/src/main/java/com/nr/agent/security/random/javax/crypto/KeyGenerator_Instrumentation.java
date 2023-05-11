package com.nr.agent.security.random.javax.crypto;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.HashCryptoOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.security.Provider;

import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.DEFAULT;
import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.LOW_SEVERITY_HOOKS_ENABLED;

@Weave(type = MatchType.ExactClass, originalName = "javax.crypto.KeyGenerator")
public class KeyGenerator_Instrumentation {
    public static final KeyGenerator_Instrumentation getInstance(String algorithm) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled){
            operation = preprocessSecurityHook(algorithm, StringUtils.EMPTY, KeyGenerator_Instrumentation.class.getName(), "getInstance", "KEYGENERATOR");
        }
        KeyGenerator_Instrumentation returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(operation);
            }
        }
        return returnValue;
    }

    public static final KeyGenerator_Instrumentation getInstance(String algorithm, String provider) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled){
            operation = preprocessSecurityHook(algorithm, provider, KeyGenerator_Instrumentation.class.getName(), "getInstance", "KEYGENERATOR");
        }
        KeyGenerator_Instrumentation returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(operation);
            }
        }
        return returnValue;
    }

    public static final KeyGenerator_Instrumentation getInstance(String algorithm, Provider provider) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled){
            operation = preprocessSecurityHook(algorithm, provider.getClass().getSimpleName(), KeyGenerator_Instrumentation.class.getName(), "getInstance", "KEYGENERATOR");
        }
        KeyGenerator_Instrumentation returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(operation);
            }
        }
        return returnValue;
    }

    private static AbstractOperation preprocessSecurityHook(String algorithm, String provider, String className, String methodName, String category) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            HashCryptoOperation operation = new HashCryptoOperation(algorithm, className, methodName, VulnerabilityCaseType.CRYPTO);
            operation.setProvider(provider);
            operation.setLowSeverityHook(true);
            operation.setEventCategory(category);

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
