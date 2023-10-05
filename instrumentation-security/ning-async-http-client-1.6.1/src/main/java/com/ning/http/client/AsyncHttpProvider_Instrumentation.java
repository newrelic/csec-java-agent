package com.ning.http.client;

import com.newrelic.agent.security.instrumentation.ning.http_1_6_1.NingHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.Future;

@Weave(type = MatchType.Interface, originalName = "com.ning.http.client.AsyncHttpProvider")
public class AsyncHttpProvider_Instrumentation {

    public <T> ListenableFuture<T> execute(Request request, AsyncHandler<T> handler) throws IOException {
        boolean isLockAcquired = NingHelper.acquireLockIfPossible(this.hashCode());
        AbstractOperation operation = null;
        URI uri = null;
        ListenableFuture<T> returnObj = null;

        try {
            uri = new URI(request.getUrl());
            String scheme = uri.getScheme();

            if (isLockAcquired && (scheme == null || scheme.equals("http") || scheme.equals("https"))) {
                operation = NingHelper.preprocessSecurityHook(request, uri.toString(), NingHelper.METHOD_NAME_EXECUTE, this.getClass().getName());
            }
        } catch (URISyntaxException uriSyntaxException) {
            // Instrumentation won't work and normal execution will continue
        }

        try {
            returnObj = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                NingHelper.releaseLock(this.hashCode());
            }
        }
        NingHelper.registerExitOperation(isLockAcquired, operation);

        return returnObj;
    }
}
