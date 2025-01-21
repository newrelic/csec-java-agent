/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.*;
import com.newrelic.api.agent.security.instrumentation.helpers.InputStreamHelper;

@Weave(type = MatchType.BaseClass, originalName = "java.io.InputStream")
public abstract class InputStream_Instrumentation {

    private boolean acquireLockIfPossible(int hashCode) {
        if(InputStreamHelper.processRequestInputStreamHookData(hashCode)) {
            return GenericHelper.acquireLockIfPossible(InputStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        }
        return false;
    }

    private void releaseLock(int hashCode) {
        GenericHelper.releaseLock(InputStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
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


    private void postProcessSecurityHook(byte[] dataBuffer, boolean isLockAcquired, int offset, int readDataLength) {
        try {
            if(isLockAcquired && readDataLength>0){
                char[] data = new char[readDataLength];
                for (int i = offset, y = 0; i < offset + readDataLength; i++, y++) {
                    data[y] = (char) dataBuffer[i];
                }
                //                            System.out.println("Writing from IS 2" + this.hashCode() + " : " + String.valueOf(data));
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(data);

            }
        } catch (Throwable e) {
            String message = "Instrumentation library: %s , error while reading stream : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, "JAVA-IO-INPUTSTREAM-JDK8", e.getMessage()), e, this.getClass().getName());
        }
    }

}
