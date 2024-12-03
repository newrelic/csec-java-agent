/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package jakarta.servlet;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.servlet5.ServletResponseCallback;

import java.io.IOException;

@Weave(type = MatchType.BaseClass, originalName = "jakarta.servlet.ServletOutputStream")
public abstract class ServletOutputStream_Instrumentation {

    private boolean acquireLockIfPossible(int hashCode) {
        try {
            if(ServletResponseCallback.processResponseOutputStreamHookData(hashCode)) {
                return GenericHelper.acquireLockIfPossible(ServletResponseCallback.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private void releaseLock(int hashCode) {
        GenericHelper.releaseLock(ServletResponseCallback.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
    }

    protected ServletOutputStream_Instrumentation(){}

    public void write(int b) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append((char) b);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }

    public void print(String o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }

    public void print(boolean o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void print(char o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void print(int o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void print(long o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void print(float o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void print(double o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void println() throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void println(String o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void println(boolean o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void println(char o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void println(int o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void println(long o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void println(float o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }
    public void println(double o) throws IOException {
        boolean isLockAcquired = acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if(isLockAcquired){
            try {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(o);
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(ServletResponseCallback.LF);
            } catch (Throwable ignored) {
//                ignored.printStackTrace(System.out);
            }
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock(this.hashCode());
            }
        }
    }

}
