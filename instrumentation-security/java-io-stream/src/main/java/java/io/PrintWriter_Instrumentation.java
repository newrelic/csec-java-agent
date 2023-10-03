/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.*;
import com.newrelic.agent.security.instrumentation.inputstream.IOStreamHelper;

import java.util.Locale;

@Weave(type = MatchType.BaseClass, originalName = "java.io.PrintWriter")
public abstract class PrintWriter_Instrumentation {
    @WeaveAllConstructors
    private PrintWriter_Instrumentation(){}

    private static boolean acquireLockIfPossible(int hashCode) {
        try {
            if(IOStreamHelper.processResponseWriterHookData(hashCode)) {
                return GenericHelper.acquireLockIfPossible(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_WRITER, hashCode);
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private static void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_WRITER, hashCode);
        } catch (Throwable ignored) {}
    }

    public PrintWriter append(char c) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
        return returnWriter;
    }

    public PrintWriter append(CharSequence csq) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
        return returnWriter;
    }

    public PrintWriter append(CharSequence csq, int start, int end) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
        return returnWriter;
    }


    public void print(boolean b) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void print(char c) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void print(int i) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void print(long l) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void print(float f) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void print(double d) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void print(char s[]) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void print(String s) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void print(Object obj) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void println() {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void println(boolean x) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void println(char x) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void println(int x) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void println(long x) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void println(float x) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void println(double x) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void println(char x[]) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void println(String x) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void println(Object x) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public void write(String s, int off, int len) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void write(String s) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void write(char buf[]) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void write(char buf[], int off, int len) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }
    public void write(int c) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
    }

    public PrintWriter printf(String format, Object ... args) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
        return returnWriter;
    }

    public PrintWriter printf(Locale l, String format, Object ... args) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
        return returnWriter;
    }
    public PrintWriter format(String format, Object ... args) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
        return returnWriter;
    }

    public PrintWriter format(Locale l, String format, Object ... args) {
        int hashcode = this.hashCode();
        boolean isLockAcquired = acquireLockIfPossible(hashcode);

        // Preprocess Phase
        if (isLockAcquired) {
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
            if(isLockAcquired){
                releaseLock(hashcode);
            }
        }
        return returnWriter;
    }

}
