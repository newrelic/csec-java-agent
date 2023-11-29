/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.javaio.io;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.InputStreamHelper;
import com.newrelic.api.agent.weaver.*;
import java.io.IOException;

@Weave(type = MatchType.BaseClass, originalName = "java.io.InputStream")
public abstract class InputStream_Instrumentation {

    private boolean acquireLockIfPossible(int hashCode) {
        try {
            if(InputStreamHelper.processRequestInputStreamHookData(hashCode)) {
                return GenericHelper.acquireLockIfPossible(InputStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(InputStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {}
    }

    public int read(byte[] b) throws IOException {
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
        postProcessSecurityHook(b, isLockAcquired, 0, returnData);

        // Normal return
        return returnData;
    }

    public int read(byte[] b, int off, int len) throws IOException {
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
        postProcessSecurityHook(b, isLockAcquired, off, returnData);

        // Normal return
        return returnData;
    }

    public byte[] readAllBytes() throws IOException {
        byte[] returnData = null;

        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }

        // Postprocess Phase
        postProcessSecurityHook(returnData, isLockAcquired, 0, returnData.length);

        // Normal return
        return returnData;
    }

    public byte[] readNBytes(int len) throws IOException {
        byte[] returnData = null;
        // Preprocess Phase
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }

        // Postprocess Phase
        postProcessSecurityHook(returnData, isLockAcquired, 0, returnData.length);

        // Normal return
        return returnData;
    }

    public int readNBytes(byte[] b, int off, int len) throws IOException {
        int returnData = -1;
        // Preprocess Phase
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }

        // Postprocess Phase
        postProcessSecurityHook(b, isLockAcquired, off, returnData);

        // Normal return
        return returnData;
    }

    // TODO : need to implement the following interception
//    public long transferTo(OutputStream out) throws IOException {}



    private void postProcessSecurityHook(byte[] dataBuffer, boolean isLockAcquired, int offset, int readDataLength) {
        try {
//                System.out.println("Done IS2 "+ this.hashCode());
            if(isLockAcquired && readDataLength>0){
                char[] data = new char[readDataLength];
                for (int i = offset, y = 0; i < offset + readDataLength; i++, y++) {
                    data[y] = (char) dataBuffer[i];
                }
                //                            System.out.println("Writing from IS 2" + this.hashCode() + " : " + String.valueOf(data));
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(data);

            }
//                System.out.println("Done out IS2 "+ this.hashCode());
        } catch (Throwable ignored) {
//                ignored.printStackTrace();
        }
    }

}
