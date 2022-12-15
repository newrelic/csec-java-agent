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

import java.util.Locale;

@Weave(type = MatchType.BaseClass, originalName = "java.io.PrintWriter")
public abstract class PrintWriter_Instrumentation {
    @NewField
    public boolean cascadedCall;

    @WeaveAllConstructors
    private PrintWriter_Instrumentation(){}

    private boolean preprocessSecurityHook(boolean currentCascadedCall) {
        try {
            if(!NewRelicSecurity.isHookProcessingActive()) {
                return false;
            }
            boolean dataGatheringAllowed = IOStreamHelper.processResponseWriterHookData(this.hashCode());
            if (Boolean.TRUE.equals(dataGatheringAllowed) && !currentCascadedCall) {
                cascadedCall = true;
                return true;
            }
        } catch(Throwable ignored) {
            ignored.printStackTrace();
        }
        return false;
    }

    private void postProcessSecurityHook(boolean currentCascadedCall) {
        cascadedCall = currentCascadedCall;
    }

    public PrintWriter append(char c) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(c);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        PrintWriter returnWriter = null;
        // Actual Call
        try {
            returnWriter = Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
        return returnWriter;
    }

    public PrintWriter append(CharSequence csq) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(csq);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        PrintWriter returnWriter = null;
        // Actual Call
        try {
            returnWriter = Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
        return returnWriter;
    }

    public PrintWriter append(CharSequence csq, int start, int end) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(csq, start, end);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        PrintWriter returnWriter = null;
        // Actual Call
        try {
            returnWriter = Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
        return returnWriter;
    }


    public void print(boolean b) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(b);
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

    public void print(char c) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(c);
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

    public void print(int i) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(i);
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

    public void print(long l) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(l);
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

    public void print(float f) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(f);
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

    public void print(double d) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(d);
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

    public void print(char s[]) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(s);
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

    public void print(String s) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(s);
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

    public void print(Object obj) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(obj);
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

    public void println() {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
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

    public void println(boolean x) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(x);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
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
    public void println(char x) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(x);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
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
    public void println(int x) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(x);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
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
    public void println(long x) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(x);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
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
    public void println(float x) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(x);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
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
    public void println(double x) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(x);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
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
    public void println(char x[]) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(x);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
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
    public void println(String x) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(x);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
            } catch (Throwable ignored) {
                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
    }
    public void println(Object x) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(x);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(IOStreamHelper.LF);
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

    public void write(String s, int off, int len) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(s, off, len);
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
    public void write(String s) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(s);
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
    public void write(char buf[]) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(buf);
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
    public void write(char buf[], int off, int len) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(buf, off, len);
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
    public void write(int c) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(c);
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

    public PrintWriter printf(String format, Object ... args) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(String.format(format, args));
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        PrintWriter returnWriter = null;
        // Actual Call
        try {
            returnWriter = Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
        return returnWriter;
    }

    public PrintWriter printf(Locale l, String format, Object ... args) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(String.format(l, format, args));
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        PrintWriter returnWriter = null;
        // Actual Call
        try {
            returnWriter = Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
        return returnWriter;
    }
    public PrintWriter format(String format, Object ... args) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(String.format(format, args));
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        PrintWriter returnWriter = null;
        // Actual Call
        try {
            returnWriter = Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
        return returnWriter;
    }

    public PrintWriter format(Locale l, String format, Object ... args) {
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        if(preprocessSecurityHook(currentCascadedCall)){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(String.format(l, format, args));
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        PrintWriter returnWriter = null;
        // Actual Call
        try {
            returnWriter = Weaver.callOriginal();
        } finally {
            postProcessSecurityHook(currentCascadedCall);
        }
        return returnWriter;
    }

}
