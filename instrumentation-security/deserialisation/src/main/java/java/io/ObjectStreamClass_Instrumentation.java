package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.DeserializationInvocation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.BaseClass, originalName = "java.io.ObjectStreamClass")
public class ObjectStreamClass_Instrumentation {

    void invokeReadObject(Object obj, ObjectInputStream in)
            throws ClassNotFoundException, IOException,
            UnsupportedOperationException
    {
        if(NewRelicSecurity.isHookProcessingActive()) {
            DeserializationInvocation deserializationInvocation = NewRelicSecurity.getAgent().getSecurityMetaData().getDeserializationInvocation();
            if (deserializationInvocation != null) {
                deserializationInvocation.pushReadObjectInAction(obj.getClass().getName());
            }
            Weaver.callOriginal();
            if (deserializationInvocation != null) {
                deserializationInvocation.popReadObjectInAction();
            }
        }
    }
}
