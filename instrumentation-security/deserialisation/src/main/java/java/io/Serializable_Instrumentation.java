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

        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addToDeserializingObjectStack(
                        new DeserializationInfo(obj.getClass().getName(), obj)
                );
            }
            Weaver.callOriginal();

            DeserialisationOperation operation = new DeserialisationOperation(
                    this.getClass().getName(),
                    SecurityHelper.METHOD_NAME_READ_OBJECT
            );

            NewRelicSecurity.getAgent().registerOperation(operation);

        } catch(Exception e){

        } finally {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().popFromDeserializingObjectStack();
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