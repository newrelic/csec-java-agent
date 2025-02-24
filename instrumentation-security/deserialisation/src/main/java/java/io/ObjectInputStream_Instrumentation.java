package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.DeserializationInfo;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.DeserialisationOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;


@Weave(type = MatchType.ExactClass, originalName = "java.io.ObjectInputStream")
public abstract class ObjectInputStream_Instrumentation {

    private void readSerialData(Object obj, ObjectStreamClass desc)
            throws IOException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        DeserializationInfo dInfo = null;
        if(isLockAcquired) {
            dInfo = preProcessSecurityHook(obj);
        }
        try {
            Weaver.callOriginal();
            operation = postProcessSecurityHook(dInfo);
        } finally {
            if(isLockAcquired) {
                finalProcessSecurityHook(dInfo);
                GenericHelper.releaseLock(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME);
            }
        }
        //TODO add register exit operation if required
    }

    private DeserializationInfo preProcessSecurityHook(Object obj) {
        DeserializationInfo dInfo = new DeserializationInfo(obj.getClass().getName(), obj);
        NewRelicSecurity.getAgent().getSecurityMetaData().addToDeserializationRoot(dInfo);
        return dInfo;
    }

    private DeserialisationOperation postProcessSecurityHook(DeserializationInfo dInfo) {
        if (dInfo != null && NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() == dInfo) {
            DeserialisationOperation operation = new DeserialisationOperation(
                    this.getClass().getName(),
                    SecurityHelper.METHOD_NAME_READ_OBJECT
            );
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        }
        return null;
    }

    private void finalProcessSecurityHook(DeserializationInfo dInfo) {
        if (dInfo != null &&
                NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() != null &&
                NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() == dInfo) {
            NewRelicSecurity.getAgent().getSecurityMetaData().resetDeserializationRoot();
        }
    }

    private boolean acquireLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.UNSAFE_DESERIALIZATION, SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME);
    }
}