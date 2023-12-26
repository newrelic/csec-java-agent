package com.sun.net.httpserver;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import java.io.InputStream;

import static com.sun.net.httpserver.HttpServerHelper.SUN_NET_READER_OPERATION_LOCK;

@Weave(type = MatchType.BaseClass, originalName = "com.sun.net.httpserver.HttpExchange")
public class HttpExchange_Instrumentation {

    public InputStream getRequestBody () {
        boolean isLockAcquired = false;
        InputStream stream;
        try {
            isLockAcquired = GenericHelper.acquireLockIfPossible(SUN_NET_READER_OPERATION_LOCK);
            stream = Weaver.callOriginal();
            if (isLockAcquired && NewRelicSecurity.isHookProcessingActive() && stream != null) {
                HttpServerHelper.registerInputStreamHashIfNeeded(stream.hashCode());
            }
        } finally {
            if(isLockAcquired) {
                GenericHelper.releaseLock(SUN_NET_READER_OPERATION_LOCK);
            }
        }
        return stream;
    }
}
