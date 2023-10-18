package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.DeserializationInfo;
import com.newrelic.api.agent.security.schema.operation.DeserialisationOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;


@Weave(type = MatchType.ExactClass, originalName = "java.io.ObjectInputStream")
public abstract class Serializable_Instrumentation {

    private void readSerialData(Object obj, ObjectStreamClass desc)
            throws IOException {
        DeserializationInfo dInfo = new DeserializationInfo(obj.getClass().getName(), obj);
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                dInfo = new DeserializationInfo(obj.getClass().getName(), obj);
                NewRelicSecurity.getAgent().getSecurityMetaData().addToDeserializationRoot(dInfo);
            }

            Weaver.callOriginal();

            if (NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() == dInfo) {
                DeserialisationOperation operation = new DeserialisationOperation(
                        this.getClass().getName(),
                        SecurityHelper.METHOD_NAME_READ_OBJECT
                );

                NewRelicSecurity.getAgent().registerOperation(operation);
            }

        } catch (Exception e) {
        } finally {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() &&
                    NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() != null &&
                    NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() == dInfo) {
                NewRelicSecurity.getAgent().getSecurityMetaData().resetDeserializationRoot();
            }
        }

//        registerExitOperation(isFileLockAcquired, operation);
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
        return false;
    }
}