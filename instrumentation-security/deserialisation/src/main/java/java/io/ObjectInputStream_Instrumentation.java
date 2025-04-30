package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.*;
import com.newrelic.api.agent.security.schema.Serializable;
import com.newrelic.api.agent.security.schema.operation.DeserializationOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.Arrays;


@Weave(type = MatchType.BaseClass, originalName = "java.io.ObjectInputStream")
public abstract class ObjectInputStream_Instrumentation {

    private void readSerialData(Object obj, ObjectStreamClass desc)
            throws IOException {
        if(NewRelicSecurity.isHookProcessingActive()) {
            DeserializationInfo dInfo = preProcessSecurityHook(obj);
        }
        Weaver.callOriginal();
    }

    private void filterCheck(Class<?> clazz, int arrayLength)
            throws InvalidClassException {
        boolean isLockAcquired = acquireLockIfPossible("filterCheck");
        boolean filterCheck = false;
        try {
            Weaver.callOriginal();
            filterCheck = true;
        } finally {
            if(isLockAcquired) {
                processFilterCheck(clazz, filterCheck);
                GenericHelper.releaseLock(String.format(ObjectInputStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME, "filterCheck"));
            }
        }
    }

    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException, ClassNotFoundException
    {
        boolean isLockAcquired = acquireLockIfPossible("resolve");
        Class<?> returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                processResolveClass(desc, returnValue);
                GenericHelper.releaseLock(String.format(ObjectInputStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME, "resolve"));
            }
        }
        return returnValue;
    }

    private DeserializationInfo preProcessSecurityHook(Object obj) {
        DeserializationInfo dInfo = new DeserializationInfo(obj.getClass().getName(), obj);
        NewRelicSecurity.getAgent().getSecurityMetaData().addToDeserializationRoot(dInfo);
        return dInfo;
    }


    private final Object readObject(Class<?> type)
            throws IOException, ClassNotFoundException {
        boolean isLockAcquired = acquireLockIfPossible("readObject");
        DeserializationInvocation deserializationInvocation = null;
        DeserializationOperation operation = null;

        if(isLockAcquired) {
            operation = new DeserializationOperation(
                    this.getClass().getName(),
                    ObjectInputStreamHelper.METHOD_NAME_READ_OBJECT
            );
            deserializationInvocation = new DeserializationInvocation(true, operation.getExecutionId());
            NewRelicSecurity.getAgent().getSecurityMetaData().setDeserializationInvocation(deserializationInvocation);
            operation.setDeserializationInvocation(deserializationInvocation);
//            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(InstrumentationConstants.ACTIVE_DESERIALIZATION, true);
        }
        try {
            return Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                if(NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() != null) {
                    operation.setRootDeserializationInfo(NewRelicSecurity.getAgent().getSecurityMetaData()
                            .peekDeserializationRoot());
                    operation.setEntityName(operation.getRootDeserializationInfo().getType());
                }
                NewRelicSecurity.getAgent().registerOperation(operation);
                NewRelicSecurity.getAgent().getSecurityMetaData().setDeserializationInvocation(null);
                NewRelicSecurity.getAgent().getSecurityMetaData().resetDeserializationRoot();
                GenericHelper.releaseLock(String.format(ObjectInputStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME, "readObject"));
            }
        }
    }

    private void processFilterCheck(Class<?> clazz, boolean filterCheck) {

        DeserializationInvocation deserializationInvocation = NewRelicSecurity.getAgent().getSecurityMetaData().getDeserializationInvocation();
        if(deserializationInvocation != null && clazz != null) {
            com.newrelic.api.agent.security.schema.Serializable serializable = deserializationInvocation.getEncounteredSerializableByName(clazz.getName());
            if(serializable == null) {
                serializable = new Serializable(clazz.getName(), true);
                serializable.setKlass(clazz);
                deserializationInvocation.addEncounteredSerializable(serializable);
//                serializable.setClassDefinition(getClassDefinition(ObjectStreamClass.lookup(clazz)));
            }
            if(!filterCheck) {
                serializable.setDeserializable(false);
            }
        }
    }

    private void processResolveClass(ObjectStreamClass desc, Class<?> returnValue) {
        DeserializationInvocation deserializationInvocation = NewRelicSecurity.getAgent().getSecurityMetaData().getDeserializationInvocation();
        if(deserializationInvocation != null) {
            Serializable serializable = deserializationInvocation.getEncounteredSerializableByName(desc.getName());
            if(serializable == null) {
                serializable = new Serializable(desc.getName(), true);
                serializable.setKlass(returnValue);
                deserializationInvocation.addEncounteredSerializable(serializable);
//                serializable.setClassDefinition(getClassDefinition(desc));
            }
            if(returnValue == null) {
                serializable.setDeserializable(false);
            }
        }
    }

    private boolean acquireLockIfPossible(String operation) {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.UNSAFE_DESERIALIZATION, String.format(ObjectInputStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME, operation));
    }
}