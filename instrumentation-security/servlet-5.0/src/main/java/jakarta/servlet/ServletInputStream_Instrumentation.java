/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package jakarta.servlet;

import com.newrelic.api.agent.security.NewRelicSecurity;;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.servlet5.ServletRequestCallback;

import java.io.IOException;

@Weave(type = MatchType.BaseClass, originalName = "jakarta.servlet.ServletInputStream")
public abstract class ServletInputStream_Instrumentation{
    @NewField
    public Boolean servletInputStreamDataGatheringAllowed;

    @NewField
    public boolean cascadedCall;

    protected ServletInputStream_Instrumentation(){}

    public int read() throws IOException {
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
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append((char) returnData);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Normal return
        return returnData;
    }

    public int readLine(byte[] b, int off, int len) throws IOException {
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
        if(postProcessSecurityHook(currentCascadedCall) && returnData > 0) {
            try {
                char[] data = new char[returnData];
                for (int i = off, y = 0; i < off + returnData; i++, y++) {
                    data[y] = (char) b[i];
                }
//                    System.out.println("Writing from IS 4" + this.hashCode() + " : " + String.valueOf(data));
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(data);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }
        // Normal return
        return returnData;
    }

    private void preprocessSecurityHook(boolean currentCascadedCall) {
        try {
            if(Boolean.FALSE.equals(servletInputStreamDataGatheringAllowed) ||
                    !NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
//                System.out.println("Start IS2 "+ this.hashCode());
            if (servletInputStreamDataGatheringAllowed == null) {
                servletInputStreamDataGatheringAllowed = ServletRequestCallback.processRequestInputStreamHookData(this.hashCode());
            }

            if (Boolean.TRUE.equals(servletInputStreamDataGatheringAllowed) && !currentCascadedCall) {
                cascadedCall = true;
            }
        } catch (Throwable ignored) {
//                ignored.printStackTrace();
        }

    }


    private boolean postProcessSecurityHook(boolean currentCascadedCall) {
        try {
            if(Boolean.FALSE.equals(servletInputStreamDataGatheringAllowed) ||
                    !NewRelicSecurity.isHookProcessingActive()) {
                return false;
            }
            if (Boolean.TRUE.equals(servletInputStreamDataGatheringAllowed) && !currentCascadedCall) {
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
