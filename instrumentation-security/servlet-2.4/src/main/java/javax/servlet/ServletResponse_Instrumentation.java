/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package javax.servlet;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.servlet24.ServletResponseCallback;

import java.io.IOException;
import java.io.PrintWriter;

@Weave(type = MatchType.Interface, originalName = "javax.servlet.ServletResponse")
public abstract class ServletResponse_Instrumentation {

    public ServletOutputStream_Instrumentation getOutputStream() throws IOException {
        ServletOutputStream_Instrumentation obj = Weaver.callOriginal();
        if(NewRelicSecurity.isHookProcessingActive() && obj != null) {
            obj.servletOutputStreamDataGatheringAllowed = true;
            ServletResponseCallback.registerOutputStreamHashIfNeeded(obj.hashCode());
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseContentType(getContentType());
//            System.out.println("Allowing data gathering for servlet OS : " + obj.hashCode());
        }
        return obj;
    }


    public PrintWriter getWriter() throws IOException{
        PrintWriter obj = Weaver.callOriginal();
        if(NewRelicSecurity.isHookProcessingActive() && obj != null) {
            ServletResponseCallback.registerWriterHashIfNeeded(obj.hashCode());
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseContentType(getContentType());
        }
        return obj;
    }

    public abstract String getContentType();

    // TODO : Read all the fetched headers
}
