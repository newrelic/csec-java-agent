package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.DeserializationInfo;
import com.newrelic.api.agent.security.schema.operation.DeserialisationOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;


@Weave(type = MatchType.ExactClass, originalName = "java.io.ObjectInputStream")
public abstract class Serializable_Instrumentation {

    private void readSerialData(Object obj, ObjectStreamClass desc)
            throws IOException {
        DeserializationInfo dInfo = preProcessSecurityHook(obj);
        try {
            Weaver.callOriginal();
            postProcessSecurityHook(dInfo);
        } finally {
            finalProcessSecurityHook(dInfo);
        }
    }

    private DeserializationInfo preProcessSecurityHook(Object obj) {
        if (NewRelicSecurity.isHookProcessingActive() &&
                !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            DeserializationInfo dInfo = new DeserializationInfo(obj.getClass().getName(), obj);
            NewRelicSecurity.getAgent().getSecurityMetaData().addToDeserializationRoot(dInfo);
            return dInfo;
        }
        return null;
    }

    private void postProcessSecurityHook(DeserializationInfo dInfo) {
        if (dInfo != null && NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() == dInfo) {
            DeserialisationOperation operation = new DeserialisationOperation(
                    this.getClass().getName(),
                    SecurityHelper.METHOD_NAME_READ_OBJECT
            );
            NewRelicSecurity.getAgent().registerOperation(operation);
        }
    }

    private void finalProcessSecurityHook(DeserializationInfo dInfo) {
        if (dInfo != null && NewRelicSecurity.isHookProcessingActive() &&
                !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() &&
                NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() != null &&
                NewRelicSecurity.getAgent().getSecurityMetaData().peekDeserializationRoot() == dInfo) {
            NewRelicSecurity.getAgent().getSecurityMetaData().resetDeserializationRoot();
        }
    }
}