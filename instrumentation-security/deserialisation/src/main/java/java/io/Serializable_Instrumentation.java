package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.DeserializationInfo;
import com.newrelic.api.agent.security.schema.operation.DeserialisationOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;


@Weave(type = MatchType.BaseClass, originalName = "java.io.ObjectStreamClass")
public abstract class Serializable_Instrumentation {

    void invokeReadObject(Object obj, ObjectInputStream in)
            throws ClassNotFoundException, IOException,
            UnsupportedOperationException {
        if (NewRelicSecurity.isHookProcessingActive() &&
                !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            try {

                NewRelicSecurity.getAgent().getSecurityMetaData().addToDeserializingObjectStack(
                        new DeserializationInfo(obj.getClass().getName(), obj)
                );
            } catch (Exception e){
                e.printStackTrace();
            }
            System.out.println("IN invokeReadObject");
        }
        try {
            System.out.println("CALLING original");
            Weaver.callOriginal();
            System.out.println("Will create DeserialisationOperation");
            DeserialisationOperation operation = new DeserialisationOperation(
                    this.getClass().getName(),
                    SecurityHelper.METHOD_NAME_READ_OBJECT
            );
            System.out.println("Created DeserialisationOperation");
            NewRelicSecurity.getAgent().registerOperation(operation);
            System.out.println("Registered DeserialisationOperation");

        } finally {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().popFromDeserializingObjectStack();
            }
        }
//        registerExitOperation(isFileLockAcquired, operation);
    }

    void invokeReadObjectNoData(Object obj)
            throws IOException, UnsupportedOperationException{
        boolean isLockAcquired = acquireLockIfPossible();
        if (isLockAcquired && NewRelicSecurity.isHookProcessingActive() &&
                !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            try {

                NewRelicSecurity.getAgent().getSecurityMetaData().addToDeserializingObjectStack(
                        new DeserializationInfo(obj.getClass().getName(), obj)
                );
            } catch (Exception e){
                e.printStackTrace();
            }
        }
        try {
            Weaver.callOriginal();

            DeserialisationOperation operation = new DeserialisationOperation(
                    this.getClass().getName(),
                    SecurityHelper.METHOD_NAME_READ_OBJECT
            );
            NewRelicSecurity.getAgent().registerOperation(operation);

        } finally {
            if (isLockAcquired && NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().popFromDeserializingObjectStack();
            }
            if (isLockAcquired){
                releaseLock();
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