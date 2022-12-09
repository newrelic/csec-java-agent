/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

//@Weave(type = MatchType.BaseClass, originalName = "java.io.PrintWriter")
public abstract class PrintWriter_Instrumentation {
//
//    @NewField
//    public Boolean dataGatheringAllowed;
//
//    @NewField
//    public boolean cascadedCall;
//
//    @WeaveAllConstructors
//    private PrintWriter_Instrumentation(){}
//
//    private boolean preprocessSecurityHook(boolean isHookProcessingActive, boolean currentCascadedCall) {
//        if(!isHookProcessingActive) {
//            return false;
//        }
//        try {
////                System.out.println("Start IS2 "+ this.hashCode());
//            if(dataGatheringAllowed == null) {
//                dataGatheringAllowed = Helper.processResponseWriterHookData(this.hashCode());
//            }
//
//            if (dataGatheringAllowed && !currentCascadedCall) {
//                cascadedCall = true;
//                return true;
//            }
//        } catch(Throwable ignored) {
//            ignored.printStackTrace();
//        }
//        return false;
//    }
//
//    private void postProcessSecurityHook(boolean isHookProcessingActive, boolean currentCascadedCall) {
//        if(isHookProcessingActive && dataGatheringAllowed != null && dataGatheringAllowed) {
//            cascadedCall = currentCascadedCall;
//        }
//    }
//
//    public PrintWriter append(char c) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(c);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            return Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public PrintWriter append(CharSequence csq) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(csq);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            return Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public PrintWriter append(CharSequence csq, int start, int end) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(csq, start, end);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            return Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//
//    public void print(boolean b) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(b);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void print(char c) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(c);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void print(int i) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(i);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void print(long l) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(l);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void print(float f) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(f);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void print(double d) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(d);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void print(char s[]) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(s);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void print(String s) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(s);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void print(Object obj) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(obj);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void println() {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void println(boolean x) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                StringBuilder builder = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody();
//                builder.append(x);
//                builder.append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//    public void println(char x) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                StringBuilder builder = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody();
//                builder.append(x);
//                builder.append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//    public void println(int x) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                StringBuilder builder = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody();
//                builder.append(x);
//                builder.append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//    public void println(long x) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                StringBuilder builder = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody();
//                builder.append(x);
//                builder.append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//    public void println(float x) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                StringBuilder builder = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody();
//                builder.append(x);
//                builder.append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//    public void println(double x) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                StringBuilder builder = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody();
//                builder.append(x);
//                builder.append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//    public void println(char x[]) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                StringBuilder builder = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody();
//                builder.append(x);
//                builder.append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//    public void println(String x) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                StringBuilder builder = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody();
//                builder.append(x);
//                builder.append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//    public void println(Object x) {
//        boolean currentCascadedCall = cascadedCall;
//        boolean isHookProcessingActive = NewRelicSecurity.isHookProcessingActive();
//
//        // Preprocess Phase
//        if(preprocessSecurityHook(isHookProcessingActive, currentCascadedCall)){
//            try {
//                StringBuilder builder = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody();
//                builder.append(x);
//                builder.append(Helper.LF);
//            } catch (Throwable ignored) {}
//        }
//
//        try {
//            Weaver.callOriginal();
//        } finally {
//            postProcessSecurityHook(isHookProcessingActive, currentCascadedCall);
//        }
//    }
//
//    public void write(String s, int off, int len) {}
//    public void write(String s) {}
//    public void write(char buf[]) {}
//    public void write(char buf[], int off, int len) {}
//    public void write(int c) {}
//
//    public PrintWriter printf(String format, Object ... args) {}
//    public PrintWriter printf(Locale l, String format, Object ... args) {}
//    public PrintWriter format(String format, Object ... args) {}
//    public PrintWriter format(Locale l, String format, Object ... args) {}

}
