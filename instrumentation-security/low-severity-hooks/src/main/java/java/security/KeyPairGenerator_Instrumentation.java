package java.security;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.agent.security.random.CryptoUtils;

import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.DEFAULT;
import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.LOW_SEVERITY_HOOKS_ENABLED;

@Weave(type = MatchType.ExactClass, originalName = "java.security.KeyPairGenerator")
public class KeyPairGenerator_Instrumentation {
    public static KeyPairGenerator getInstance(String algorithm) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled){
            operation = CryptoUtils.preprocessSecurityHook(algorithm, StringUtils.EMPTY, KeyPairGenerator.class.getName(), "getInstance", "KEYPAIRGENERATOR");
        }
        KeyPairGenerator returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                CryptoUtils.registerExitOperation(operation);
            }
        }
        return returnValue;
    }

    public static KeyPairGenerator getInstance(String algorithm, String provider) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled){
            operation = CryptoUtils.preprocessSecurityHook(algorithm, provider, KeyPairGenerator.class.getName(), "getInstance", "KEYPAIRGENERATOR");
        }
        KeyPairGenerator returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                CryptoUtils.registerExitOperation(operation);
            }
        }
        return returnValue;
    }

    public static KeyPairGenerator getInstance(String algorithm, Provider provider) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled){
            operation = CryptoUtils.preprocessSecurityHook(algorithm, provider.getClass().getSimpleName(), KeyPairGenerator.class.getName(), "getInstance", "KEYPAIRGENERATOR");
        }
        KeyPairGenerator returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                CryptoUtils.registerExitOperation(operation);
            }
        }
        return returnValue;
    }
}
