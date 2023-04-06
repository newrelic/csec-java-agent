/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.javaio.IOStreamHelper;

@Weave(type = MatchType.BaseClass, originalName = "java.io.OutputStream")
public abstract class OutputStream_Instrumentation {
    private static boolean acquireLockIfPossible(int hashCode) {
        try {
            if(IOStreamHelper.processResponseOutputStreamHookData(hashCode)) {
                return GenericHelper.acquireLockIfPossible(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_OUTPUT_STREAM, hashCode);
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private static void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_OUTPUT_STREAM, hashCode);
        } catch (Throwable ignored) {}
    }
    
    public void write(byte b[]) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if (isLockAcquired && b != null) {
            IOStreamHelper.preprocessSecurityHook(b, 0, b.length);
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }

    public void write(byte b[], int off, int len) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if (isLockAcquired && b != null) {
            IOStreamHelper.preprocessSecurityHook(b, off, len);
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }

}
