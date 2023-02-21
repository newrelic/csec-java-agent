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
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.javaio.IOStreamHelper;

@Weave(type = MatchType.BaseClass, originalName = "java.io.BufferedReader")
public abstract class BufferedReader_Instrumentation {

    @WeaveAllConstructors
    private BufferedReader_Instrumentation(){}

    public int read() throws IOException {
        int returnData = -1;
        boolean isLockAcquired = acquireLockIfPossible();
        // Preprocess Phase
        boolean isDataGatheringAllowed = isLockAcquired && preprocessSecurityHook();

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }

        // Postprocess Phase
        if (isDataGatheringAllowed && returnData > 0) {
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
        boolean isLockAcquired = acquireLockIfPossible();
        // Preprocess Phase
        boolean isDataGatheringAllowed = isLockAcquired && preprocessSecurityHook();

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }

        // Postprocess Phase
        if (isDataGatheringAllowed && returnData > 0) {
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(cbuf, off, returnData);
            } catch (Throwable ignored) {
//                    ignored.printStackTrace(System.out);
            }
        }
        // Normal return
        return returnData;
    }

    public String readLine() throws IOException {
        String returnData = null;
        boolean isLockAcquired = acquireLockIfPossible();
        // Preprocess Phase
        boolean isDataGatheringAllowed = isLockAcquired && preprocessSecurityHook();

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }

        // Postprocess Phase
        if (isDataGatheringAllowed && returnData != null) {
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(returnData);
            } catch (Throwable ignored) {
//                    ignored.printStackTrace(System.out);
            }
        }
        // Normal return
        return returnData;
    }

    // TODO: need way to clone or intercept this stream elements
//    public Stream<String> lines() {}

    private boolean preprocessSecurityHook() {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                return false;
            }
            boolean dataGatheringAllowed = IOStreamHelper.processRequestReaderHookData(this.hashCode());
            if (Boolean.TRUE.equals(dataGatheringAllowed)) {
                return true;
            }
        } catch (Throwable ignored) {
//                ignored.printStackTrace();
        }
        return false;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_READER, this.hashCode());
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_READER, this.hashCode());
        } catch (Throwable ignored) {
        }
        return false;
    }

}
