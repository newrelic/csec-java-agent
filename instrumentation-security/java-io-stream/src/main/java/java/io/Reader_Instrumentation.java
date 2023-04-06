/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.javaio.IOStreamHelper;

@Weave(type = MatchType.BaseClass, originalName = "java.io.Reader")
public abstract class Reader_Instrumentation {

    protected Object lock;

    private boolean acquireLockIfPossible(int hashCode) {
        try {
            if(IOStreamHelper.processRequestReaderHookData(hashCode)) {
                return GenericHelper.acquireLockIfPossible(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_READER, hashCode);
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_READER, hashCode);
        } catch (Throwable ignored) {}
    }

    protected Reader_Instrumentation(){
        this.lock = this;
    }

    public int read(char cbuf[]) throws IOException {
        int returnData = -1;
        int hashCode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashCode);

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode);
            }
        }
        // Postprocess Phase
        if (isLockAcquired && returnData > 0) {
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(cbuf, 0, returnData);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Normal return
        return returnData;
    }

    public int read(java.nio.CharBuffer target) throws IOException {
        int returnData = -1;
        int hashCode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashCode);

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(hashCode);
            }
        }

        // Postprocess Phase
        if (isLockAcquired && returnData > 0) {
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(target.array(), 0, returnData);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Normal return
        return returnData;
    }

}
