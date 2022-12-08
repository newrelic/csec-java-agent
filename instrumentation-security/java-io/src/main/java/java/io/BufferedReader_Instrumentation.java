/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.*;
import com.nr.instrumentation.security.javaio.Helper;

@Weave(type = MatchType.BaseClass, originalName = "java.io.BufferedReader")
public abstract class BufferedReader_Instrumentation {

    @NewField
    public Boolean dataGatheringAllowed;

    @NewField
    public boolean cascadedCall;

    @WeaveAllConstructors
    private BufferedReader_Instrumentation(){}

    public int read() throws IOException {
        int returnData = -1;
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        preprocessSecurityHook(currentCascadedCall);

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }

        // Postprocess Phase
        if (postProcessSecurityHook(currentCascadedCall) && returnData > 0) {
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
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        preprocessSecurityHook(currentCascadedCall);

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }

        // Postprocess Phase
        if (postProcessSecurityHook(currentCascadedCall) && returnData > 0) {
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
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        preprocessSecurityHook(currentCascadedCall);

        // Actual Call

        try {
            returnData = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }

        // Postprocess Phase
        if (postProcessSecurityHook(currentCascadedCall) && returnData != null) {
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



    private void preprocessSecurityHook(boolean currentCascadedCall) {
        try {
            if(Boolean.FALSE.equals(dataGatheringAllowed) ||
                    !NewRelicSecurity.isHookProcessingActive()) {
                return;
            }

//                System.out.println("Start IS2 "+ this.hashCode());
            if (dataGatheringAllowed == null) {
                dataGatheringAllowed = Helper.processRequestReaderHookData(this.hashCode());
            }

            if (Boolean.TRUE.equals(dataGatheringAllowed) && !currentCascadedCall) {
                cascadedCall = true;
            }
        } catch (Throwable ignored) {
//                ignored.printStackTrace();
        }

    }


    private boolean postProcessSecurityHook(boolean currentCascadedCall) {
        try {
            if(Boolean.FALSE.equals(dataGatheringAllowed) ||
                    !NewRelicSecurity.isHookProcessingActive()) {
                return false;
            }

            if (Boolean.TRUE.equals(dataGatheringAllowed) && !currentCascadedCall) {
                return true;
            }
        } catch (Throwable ignored) {
//                ignored.printStackTrace();
        }

        return false;
    }

}
