/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.*;
import com.nr.instrumentation.security.javaio.IOStreamHelper;

@Weave(type = MatchType.BaseClass, originalName = "java.io.Reader")
public abstract class Reader_Instrumentation {

    @NewField
    public boolean cascadedCall;

    protected Object lock;

    protected Reader_Instrumentation(){
        this.lock = this;
    }

    public int read(char cbuf[]) throws IOException {
        boolean currentCascadedCall = cascadedCall;
        // Preprocess Phase
        preprocessSecurityHook(currentCascadedCall);

        // Actual Call
        int returnData = -1;
        try {
            returnData = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }

        // Postprocess Phase
        if(postProcessSecurityHook(currentCascadedCall) && returnData > 0){
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
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        preprocessSecurityHook(currentCascadedCall);

        // Actual Call
        int returnData = -1;
        try {
            returnData = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }

        // Postprocess Phase
        if(postProcessSecurityHook(currentCascadedCall) && returnData > 0){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(target.array(), 0, returnData);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Normal return
        return returnData;
    }

    private void preprocessSecurityHook(boolean currentCascadedCall) {
        try {
            if(!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }

            boolean dataGatheringAllowed = IOStreamHelper.processRequestReaderHookData(this.hashCode());
//                 System.out.println("Start IS2 "+ this.hashCode());
            if (Boolean.TRUE.equals(dataGatheringAllowed) && !currentCascadedCall) {
                cascadedCall = true;
            }
        } catch (Throwable ignored) {
//                ignored.printStackTrace();
        }

    }


    private boolean postProcessSecurityHook(boolean currentCascadedCall) {
        try {
            if(!NewRelicSecurity.isHookProcessingActive()) {
                return false;
            }
            boolean dataGatheringAllowed = IOStreamHelper.processRequestReaderHookData(this.hashCode());
            if (Boolean.TRUE.equals(dataGatheringAllowed) && !currentCascadedCall) {
                return true;
            }
        } catch (Throwable ignored) {
//                ignored.printStackTrace();
        } finally {
            cascadedCall = currentCascadedCall;
        }
        return false;
    }

}
