package javax.naming;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.utils.UserDataTranslationHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.javax.JNDIUtils;

import javax.naming.directory.SearchResult;
import java.util.Enumeration;
import java.util.List;

@Weave(type = MatchType.Interface, originalName = "javax.naming.Context")
public abstract class Context_Instrumentation {

    public Object lookup(Name name) throws NamingException {
        boolean isLockAcquired = acquireLockIfPossible();
        List<AbstractOperation> operations = null;
        if(isLockAcquired) {
            operations = preprocessSecurityHook(name.getAll(), JNDIUtils.METHOD_LOOKUP);
        }
        Object returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operations);
        return returnVal;
    }

    public Object lookupLink(Name name) throws NamingException {
        boolean isLockAcquired = acquireLockIfPossible();
        List<AbstractOperation> operations = null;
        if(isLockAcquired) {
            operations = preprocessSecurityHook(name.getAll(), JNDIUtils.METHOD_LOOKUP);
        }
        Object returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operations);
        return returnVal;
    }

    public Object lookup(String name) throws NamingException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(name, JNDIUtils.METHOD_LOOKUP);
        }
        Object returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public Object lookupLink(String name) throws NamingException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(name, JNDIUtils.METHOD_LOOKUP);
        }
        Object returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    private void registerExitOperation(boolean isLockAcquired, List<AbstractOperation> operations) {
        try {
            if(operations == null || operations.isEmpty() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()) {
                return;
            }

            for (AbstractOperation operation : operations) {
                NewRelicSecurity.getAgent().registerExitEvent(operation);
            }
        } catch (Throwable ignored){}
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
    }

    private List<AbstractOperation> preprocessSecurityHook (Enumeration<String> names, String methodName){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    names == null || !names.hasMoreElements()){
                return null;
            }
            UserDataTranslationHelper.placeJNDIAdditionalTemplateData();
            return JNDIUtils.handleJNDIHook(names, methodName, this.getClass().getName());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return null;
    }

    private AbstractOperation preprocessSecurityHook (String name, String methodName){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    StringUtils.isBlank(name)){
                return null;
            }
            UserDataTranslationHelper.placeJNDIAdditionalTemplateData();
            return JNDIUtils.handleJNDIHook(name, methodName, this.getClass().getName());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(JNDIUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(JNDIUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
        return false;
    }
}
