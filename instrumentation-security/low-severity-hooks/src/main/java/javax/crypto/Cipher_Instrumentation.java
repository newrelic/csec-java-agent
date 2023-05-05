package javax.crypto;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.agent.security.random.CryptoUtils;

import java.security.Provider;

import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.DEFAULT;
import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.LOW_SEVERITY_HOOKS_ENABLED;

@Weave(type = MatchType.ExactClass, originalName = "javax.crypto.Cipher")
public class Cipher_Instrumentation {
    public static final Cipher_Instrumentation getInstance(String algorithm) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled){
            operation = CryptoUtils.preprocessSecurityHook(algorithm, StringUtils.EMPTY, Cipher_Instrumentation.class.getName(), "getInstance", "CIPHER");
        }
        Cipher_Instrumentation returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                CryptoUtils.registerExitOperation(operation);
            }
        }
        return returnValue;
    }

    public static final Cipher_Instrumentation getInstance(String transformation, Provider provider) {
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled){
            operation = CryptoUtils.preprocessSecurityHook(transformation, provider.getClass().getSimpleName(), Cipher_Instrumentation.class.getName(), "getInstance", "CIPHER");
        }
        Cipher_Instrumentation returnValue = null;
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
