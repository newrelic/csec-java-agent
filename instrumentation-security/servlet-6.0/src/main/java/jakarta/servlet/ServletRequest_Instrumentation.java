/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package jakarta.servlet;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.servlet6.ServletRequestCallback;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Map;

import static com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper.SERVLET_GET_IS_OPERATION_LOCK;
import static com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper.SERVLET_GET_READER_OPERATION_LOCK;

@Weave(type = MatchType.Interface, originalName = "jakarta.servlet.ServletRequest")
public abstract class ServletRequest_Instrumentation {

    public ServletInputStream_Instrumentation getInputStream() throws IOException {
        boolean isLockAcquired = false;
        ServletInputStream_Instrumentation obj;
        try {
            isLockAcquired = GenericHelper.acquireLockIfPossible(SERVLET_GET_IS_OPERATION_LOCK);
            obj = Weaver.callOriginal();
            if (isLockAcquired && obj != null) {
                ServletRequestCallback.registerInputStreamHashIfNeeded(obj.hashCode());
            }
        } finally {
            if(isLockAcquired) {
                GenericHelper.releaseLock(SERVLET_GET_IS_OPERATION_LOCK);
            }
        }
        return obj;
    }


    public BufferedReader getReader() throws IOException {
        boolean isLockAcquired = false;
        BufferedReader obj;
        try {
            isLockAcquired = GenericHelper.acquireLockIfPossible(SERVLET_GET_READER_OPERATION_LOCK);
            obj = Weaver.callOriginal();
            if (isLockAcquired && obj != null) {
                ServletRequestCallback.registerReaderHashIfNeeded(obj.hashCode());
                //            System.out.println("Allowing data gathering for servlet reader : " + obj.hashCode());
            }
        } finally {
            if(isLockAcquired) {
                GenericHelper.releaseLock(SERVLET_GET_READER_OPERATION_LOCK);
            }
        }
        return obj;
    }

    public String getParameter(String name){
        String returnData = Weaver.callOriginal();
        if (NewRelicSecurity.isHookProcessingActive() && returnData != null) {
            HttpRequest securityRequest = NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
            securityRequest.getParameterMap().putIfAbsent(name, new String[]{returnData});
        }
        return returnData;
    }

    public String[] getParameterValues(String name){
        String[] returnData = Weaver.callOriginal();
        if (NewRelicSecurity.isHookProcessingActive() && returnData != null) {
            HttpRequest securityRequest = NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
            securityRequest.getParameterMap().putIfAbsent(name, returnData);
        }
        return returnData;
    }

    public Map<String, String[]> getParameterMap(){
        Map<String, String[]> returnData = Weaver.callOriginal();
        if (NewRelicSecurity.isHookProcessingActive() && returnData != null) {
            HttpRequest securityRequest = NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
            securityRequest.getParameterMap().putAll(returnData);
        }
        return returnData;
    }

}
