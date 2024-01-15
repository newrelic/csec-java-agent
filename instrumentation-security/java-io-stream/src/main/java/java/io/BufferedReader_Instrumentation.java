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
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.api.agent.security.instrumentation.helpers.IOStreamHelper;

import static com.newrelic.api.agent.security.instrumentation.helpers.IOStreamHelper.JAVA_IO_STREAM;

@Weave(type = MatchType.BaseClass, originalName = "java.io.BufferedReader")
public abstract class BufferedReader_Instrumentation {

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

    @WeaveAllConstructors
    private BufferedReader_Instrumentation(){}

    public int read() throws IOException {
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
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append((char) returnData);
            } catch (Throwable ignored) {
//                    ignored.printStackTrace(System.out);
            }
        }

        // Normal return
        return returnData;

    }

    public int read(char cbuf[], int off, int len) throws IOException {
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
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(cbuf, off, returnData);
            } catch (Throwable ignored) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(IOStreamHelper.ERROR_WHILE_READING_STREAM, JAVA_IO_STREAM, ignored.getMessage()), ignored, this.getClass().getName());
//                    ignored.printStackTrace(System.out);
            }
        }
        // Normal return
        return returnData;
    }

    public String readLine() throws IOException {
        String returnData = null;
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
        if (isLockAcquired && returnData != null) {
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(returnData);
            } catch (Throwable ignored) {
                String message = IOStreamHelper.ERROR_WHILE_READING_STREAM;
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, JAVA_IO_STREAM, ignored.getMessage()), ignored, this.getClass().getName());
//                    ignored.printStackTrace(System.out);
            }
        }
        // Normal return
        return returnData;
    }

    // TODO: need way to clone or intercept this stream elements
//    public Stream<String> lines() {}

}
