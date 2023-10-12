package com.sun.org.apache.xpath.internal;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.xpath.javax.XPATHUtils;
import com.sun.org.apache.xml.internal.utils.PrefixResolver;
import com.sun.org.apache.xpath.internal.objects.XObject;

@Weave(type = MatchType.ExactClass, originalName = "com.sun.org.apache.xpath.internal.XPath")
public abstract class XPath_Instrumentation {

    abstract public String getPatternString();

    public XObject execute(
            XPathContext xctxt, int contextNode, PrefixResolver namespaceContext)
            throws javax.xml.transform.TransformerException
    {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(getPatternString(), XPATHUtils.METHOD_EXECUTE);
        }

        XObject returnVal = null;
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

    public XObject execute(
            XPathContext xctxt, org.w3c.dom.Node contextNode,
            PrefixResolver namespaceContext)
            throws javax.xml.transform.TransformerException
    {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(getPatternString(), XPATHUtils.METHOD_EXECUTE);
        }

        XObject returnVal = null;
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

    private AbstractOperation preprocessSecurityHook (String patternString, String methodName){
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    StringUtils.isBlank(patternString)){
                return null;
            }
            XPathOperation xPathOperation = new XPathOperation(patternString, this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(xPathOperation);
            return xPathOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(XPATHUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(XPATHUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
        return false;
    }
}
