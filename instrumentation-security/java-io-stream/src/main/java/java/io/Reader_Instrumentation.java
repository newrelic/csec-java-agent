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

    protected Reader_Instrumentation(){
        this.lock = this;
    }

    public int read(char cbuf[]) throws IOException {
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
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(target.array(), 0, returnData);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Normal return
        return returnData;
    }

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
