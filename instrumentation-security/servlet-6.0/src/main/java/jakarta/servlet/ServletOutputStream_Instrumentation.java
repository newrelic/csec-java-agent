/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package jakarta.servlet;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.servlet6.ServletResponseCallback;

import java.io.IOException;

@Weave(type = MatchType.BaseClass, originalName = "jakarta.servlet.ServletOutputStream")
public abstract class ServletOutputStream_Instrumentation {
    @NewField
    public Boolean servletOutputStreamDataGatheringAllowed;

    @NewField
    public boolean cascadedCall;

    protected ServletOutputStream_Instrumentation(){}

    public void write(int b) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append((char) b);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }

    public void print(String o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }

    public void print(boolean o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void print(char o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void print(int o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void print(long o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void print(float o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void print(double o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void println() throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void println(String o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void println(boolean o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void println(char o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void println(int o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void println(long o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void println(float o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void println(double o) throws IOException {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }

    private boolean preprocessSecurityHook(boolean currentCascadedCall) {
        try {
            if(Boolean.FALSE.equals(servletOutputStreamDataGatheringAllowed) ||
                    !NewRelicSecurity.isHookProcessingActive()) {
                return false;
            }
//                System.out.println("Start IS2 "+ this.hashCode());
            if(servletOutputStreamDataGatheringAllowed == null) {
                servletOutputStreamDataGatheringAllowed = ServletResponseCallback.processResponseOutputStreamHookData(this.hashCode());
            }

            if (Boolean.TRUE.equals(servletOutputStreamDataGatheringAllowed) && !currentCascadedCall) {
                cascadedCall = true;
                return true;
//                        System.out.println("Writing from IS 2" + this.hashCode() + " : " + String.valueOf(data));
            }
        } catch(Throwable ignored) {
//            ignored.printStackTrace();
        }
        return false;
    }

    private void postProcessSecurityHook(boolean currentCascadedCall) {
        cascadedCall = currentCascadedCall;
    }
}
