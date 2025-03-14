package org.apache.xpath;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.XPathOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.xalan.xpath.XPATHUtils;
import org.apache.xml.utils.PrefixResolver;
import org.apache.xpath.objects.XObject;
import org.w3c.dom.Node;

import javax.xml.transform.TransformerException;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.xpath.XPath")
public abstract class XPath_Instrumentation {

    abstract public String getPatternString();

    public XObject execute(XPathContext var1, Node var2, PrefixResolver var3) throws TransformerException {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.XPATH);
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
            if (operation == null || !isProcessingAllowed ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, XPATHUtils.XALAN_XPATH, e.getMessage()), e, this.getClass().getName());
        }
    }

    private AbstractOperation preprocessSecurityHook (String patternString, String methodName){
        try {
            if (StringUtils.isBlank(patternString)){
                return null;
            }
            XPathOperation xPathOperation = new XPathOperation(patternString, this.getClass().getName(), methodName);
            NewRelicSecurity.getAgent().registerOperation(xPathOperation);
            return xPathOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, XPATHUtils.XALAN_XPATH, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, XPATHUtils.XALAN_XPATH, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE,
                    XPATHUtils.XALAN_XPATH, e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    private void releaseLock() {
        GenericHelper.releaseLock(XPATHUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType xpath) {
        return GenericHelper.acquireLockIfPossible(xpath, XPATHUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
    }
}
