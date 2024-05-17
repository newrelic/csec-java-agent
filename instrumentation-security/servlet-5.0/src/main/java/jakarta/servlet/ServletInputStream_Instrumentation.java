/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package jakarta.servlet;

import com.newrelic.agent.security.instrumentation.servlet5.HttpServletHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.IOStreamHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.servlet5.ServletRequestCallback;

import java.io.IOException;

@Weave(type = MatchType.BaseClass, originalName = "jakarta.servlet.ServletInputStream")
public abstract class ServletInputStream_Instrumentation{
    private boolean acquireLockIfPossible(int hashCode) {
        try {
            if(ServletRequestCallback.processRequestInputStreamHookData(hashCode)) {
                return GenericHelper.acquireLockIfPossible(ServletRequestCallback.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(ServletRequestCallback.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {}
    }

    protected ServletInputStream_Instrumentation(){}

    public int read() throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Actual Call
        int returnData = -1;
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }


        // Postprocess Phase
        if(isLockAcquired && returnData>0){
            NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append((char) returnData);
        }

        // Normal return
        return returnData;
    }

    public int readLine(byte[] b, int off, int len) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Actual Call
        int returnData = -1;
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }

        // Postprocess Phase
        if(isLockAcquired && returnData>0){
            try {
                char[] data = new char[returnData];
                for (int i = off, y = 0; i < off + returnData; i++, y++) {
                    data[y] = (char) b[i];
                }
//                    System.out.println("Writing from IS 4" + this.hashCode() + " : " + String.valueOf(data));
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(data);
            } catch (Throwable e) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(IOStreamHelper.ERROR_WHILE_READING_STREAM, HttpServletHelper.SERVLET_5_0, e.getMessage()), e, ServletInputStream_Instrumentation.class.getName());
            }
        }
        // Normal return
        return returnData;
    }

}
