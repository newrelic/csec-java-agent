package jakarta.servlet.http;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.TrustBoundaryOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.DEFAULT;
import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.LOW_SEVERITY_HOOKS_ENABLED;

@Weave(type = MatchType.Interface, originalName = "jakarta.servlet.http.HttpSession")
public class HttpSession_Instrumentation {

    public void setAttribute(String name, Object value){
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(name, value, getClass().getName(), "setAttribute");
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

    public void putValue(String name, Object value){
        boolean isLockAcquired = acquireLockIfPossible(hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);
        if (isOwaspHookEnabled){
            if (isLockAcquired)
                operation = preprocessSecurityHook(name, value, getClass().getName(), "putValue");
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

    private AbstractOperation preprocessSecurityHook(String name, Object value, String className, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            TrustBoundaryOperation operation = new TrustBoundaryOperation(name, value, className, methodName);
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
            GenericHelper.releaseLock(ServletHelper.NR_SEC_HTTP_SESSION_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible(int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(ServletHelper.NR_SEC_HTTP_SESSION_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
        return false;
    }
}
