/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package jakarta.servlet;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.servlet6.ServletResponseCallback;

import java.io.IOException;
import java.io.PrintWriter;

import static com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper.SERVLET_GET_OS_OPERATION_LOCK;
import static com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper.SERVLET_GET_WRITER_OPERATION_LOCK;

@Weave(type = MatchType.Interface, originalName = "jakarta.servlet.ServletResponse")
public abstract class ServletResponse_Instrumentation {

    public ServletOutputStream_Instrumentation getOutputStream() throws IOException {
        boolean isLockAcquired = false;
        ServletOutputStream_Instrumentation obj;
        try {
            isLockAcquired = GenericHelper.acquireLockIfPossible(SERVLET_GET_OS_OPERATION_LOCK);
            obj = Weaver.callOriginal();
            if (isLockAcquired && obj != null) {
                ServletResponseCallback.registerOutputStreamHashIfNeeded(obj.hashCode());
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setContentType(getContentType());
            }
        } finally {
            if(isLockAcquired) {
                GenericHelper.releaseLock(SERVLET_GET_OS_OPERATION_LOCK);
            }
        }
        return obj;
    }


    public PrintWriter getWriter() throws IOException{
        boolean isLockAcquired = false;
        PrintWriter obj;
        try {
            isLockAcquired = GenericHelper.acquireLockIfPossible(SERVLET_GET_WRITER_OPERATION_LOCK);
            obj = Weaver.callOriginal();
            if (isLockAcquired && obj != null) {
                ServletResponseCallback.registerWriterHashIfNeeded(obj.hashCode());
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setContentType(getContentType());
            }
        } finally {
            if(isLockAcquired) {
                GenericHelper.releaseLock(SERVLET_GET_WRITER_OPERATION_LOCK);
            }
        }
        return obj;
    }

    public abstract String getContentType();

    // TODO : Read all the fetched headers
}
