/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.javaio.Helper;

@Weave(type = MatchType.BaseClass, originalName = "java.io.OutputStream")
public abstract class OutputStream_Instrumentation {

    @NewField
    public Boolean outputStreamDataGatheringAllowed;

    @NewField
    public boolean cascadedCall;

    public void write(byte b[]) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if (b != null) {
            preprocessSecurityHook(b, currentCascadedCall, 0, b.length);
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }

    public void write(byte b[], int off, int len) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if (b != null) {
            preprocessSecurityHook(b, currentCascadedCall, off, len);
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }


    private void preprocessSecurityHook(byte[] dataBuffer, boolean currentCascadedCall,
                                        int offset, int writeDataLength) {
        try {
            if(Boolean.FALSE.equals(outputStreamDataGatheringAllowed) ||
                    !NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
//                System.out.println("Start IS2 "+ this.hashCode());
            if(outputStreamDataGatheringAllowed == null) {
                outputStreamDataGatheringAllowed = Helper.processResponseOutputStreamHookData(this.hashCode());
            }

            if (Boolean.TRUE.equals(outputStreamDataGatheringAllowed) && !currentCascadedCall && writeDataLength > -1) {
                cascadedCall = true;
                char[] data = new char[writeDataLength];
                for (int i = offset, y = 0; i < writeDataLength; i++, y++) {
                    data[y] = (char) dataBuffer[i];
                }

//                        System.out.println("Writing from IS 2" + this.hashCode() + " : " + String.valueOf(data));
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(data);
            }
        } catch(Throwable ignored) {
//            ignored.printStackTrace();
        }
    }

    private void postProcessSecurityHook(boolean currentCascadedCall) {
        cascadedCall = currentCascadedCall;
    }

}
