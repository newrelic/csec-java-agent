package com.newrelic.agent.security.instrumentation.jersey2;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.InputStream;

import static com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper.SERVLET_GET_IS_OPERATION_LOCK;

@Weave(type = MatchType.ExactClass, originalName = "org.glassfish.jersey.message.internal.EntityInputStream")
public class EntityInputStream_Instrumentation {

    public final InputStream getWrappedStream() {
        InputStream retunObject;
        boolean isLockAcquired = false;
        try {
            isLockAcquired = GenericHelper.acquireLockIfPossible(SERVLET_GET_IS_OPERATION_LOCK);
            retunObject = Weaver.callOriginal();
            if (isLockAcquired && NewRelicSecurity.isHookProcessingActive() && retunObject != null) {
                HttpRequestHelper.registerInputStreamHashIfNeeded(retunObject.hashCode());
            }
        } finally {
            if(isLockAcquired) {
                GenericHelper.releaseLock(SERVLET_GET_IS_OPERATION_LOCK);
            }
        }
        return retunObject;
    }

}
