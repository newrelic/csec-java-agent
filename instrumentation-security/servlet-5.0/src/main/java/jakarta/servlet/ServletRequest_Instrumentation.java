/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package jakarta.servlet;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.servlet5.ServletRequestCallback;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Map;

@Weave(type = MatchType.Interface, originalName = "jakarta.servlet.ServletRequest")
public abstract class ServletRequest_Instrumentation {

    public ServletInputStream_Instrumentation getInputStream() throws IOException {
        ServletInputStream_Instrumentation obj = Weaver.callOriginal();
        if(NewRelicSecurity.isHookProcessingActive() && obj != null) {
            obj.servletInputStreamDataGatheringAllowed = true;
            ServletRequestCallback.registerInputStreamHashIfNeeded(obj.hashCode());
//            System.out.println("Allowing data gathering for servlet IS : " + obj.hashCode());
        }
        return obj;
    }


    public BufferedReader getReader() throws IOException {
        BufferedReader obj = Weaver.callOriginal();
        if(NewRelicSecurity.isHookProcessingActive() && obj != null) {
            ServletRequestCallback.registerReaderHashIfNeeded(obj.hashCode());
//            System.out.println("Allowing data gathering for servlet reader : " + obj.hashCode());
        }
        return obj;
    }

    public String getParameter(String name){
        String returnData = Weaver.callOriginal();
        if(NewRelicSecurity.isHookProcessingActive()){
            HttpRequest securityRequest = NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
            securityRequest.getParameterMap().putIfAbsent(name, new String[]{returnData});
        }
        return returnData;
    }

    public String[] getParameterValues(String name){
        String[] returnData = Weaver.callOriginal();
        if(NewRelicSecurity.isHookProcessingActive()){
            HttpRequest securityRequest = NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
            securityRequest.getParameterMap().putIfAbsent(name, returnData);
        }
        return returnData;
    }

    public Map<String, String[]> getParameterMap(){
        Map<String, String[]> returnData = Weaver.callOriginal();
        if(NewRelicSecurity.isHookProcessingActive()){
            HttpRequest securityRequest = NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
            securityRequest.getParameterMap().putAll(returnData);
        }
        return returnData;
    }

}
