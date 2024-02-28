package jakarta.servlet.http;

import com.newrelic.agent.security.instrumentation.servlet5.HttpServletHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SecureCookieOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.Interface, originalName = "jakarta.servlet.http.HttpServletResponse")
public class HttpServletResponse_Instrumentation {

    public void addCookie(Cookie cookie){
        boolean isLockAcquired = acquireLockIfPossible(cookie.hashCode());
        AbstractOperation operation = null;
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();
        if (isOwaspHookEnabled && LowSeverityHelper.isOwaspHookProcessingNeeded()){
            if (isLockAcquired)
                operation = preprocessSecurityHook(cookie, getClass().getName(), "addCookie");
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(cookie.hashCode());
            }
        }
        if (isOwaspHookEnabled) {
            registerExitOperation(isLockAcquired, operation);
        }
    }

    private AbstractOperation preprocessSecurityHook(Cookie cookie, String className, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            boolean isSecure = cookie.getSecure();
            boolean isHttpOnly = cookie.isHttpOnly();
            boolean sameSiteStrict = true;
            if(NewRelicSecurity.getAgent().getServerInfo("SAME_SITE_COOKIES") != null){
                sameSiteStrict = StringUtils.equalsIgnoreCase(NewRelicSecurity.getAgent().getServerInfo("SAME_SITE_COOKIES"), "Strict");
            } else if(StringUtils.containsIgnoreCase(cookie.getValue(), "SameSite")) {
                sameSiteStrict = StringUtils.containsIgnoreCase(cookie.getValue(), "SameSite=Strict");
            }
            SecureCookieOperation operation = new SecureCookieOperation(Boolean.toString(isSecure), isSecure, isHttpOnly, sameSiteStrict, cookie.getValue(), className, methodName);
            operation.setLowSeverityHook(true);
            NewRelicSecurity.getAgent().registerOperation(operation);

            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_5_0, e.getMessage()), e, HttpServletResponse_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_5_0, e.getMessage()), e, HttpServletResponse_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_5_0, e.getMessage()), e, HttpServletResponse_Instrumentation.class.getName());
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
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_5_0, e.getMessage()), e, HttpServletResponse_Instrumentation.class.getName());
        }
    }

    private void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(ServletHelper.NR_SEC_HTTP_SERVLET_RESPONSE_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible(int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(ServletHelper.NR_SEC_HTTP_SERVLET_RESPONSE_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
        return false;
    }
}
