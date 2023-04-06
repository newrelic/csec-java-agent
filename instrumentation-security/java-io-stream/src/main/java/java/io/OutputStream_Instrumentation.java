/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.javaio.IOStreamHelper;

@Weave(type = MatchType.BaseClass, originalName = "java.io.OutputStream")
public abstract class OutputStream_Instrumentation {

    public void write(byte b[]) throws IOException {
        boolean isLockAcquired = IOStreamHelper.acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if (isLockAcquired && b != null) {
            IOStreamHelper.preprocessSecurityHook(b, 0, b.length);
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                IOStreamHelper.releaseLock(this.hashCode());
            }
        }
    }

    public void write(byte b[], int off, int len) throws IOException {
        boolean isLockAcquired = IOStreamHelper.acquireLockIfPossible(this.hashCode());

        // Preprocess Phase
        if (isLockAcquired && b != null) {
            IOStreamHelper.preprocessSecurityHook(b, off, len);
        }

        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                IOStreamHelper.releaseLock(this.hashCode());
            }
        }
    }

}
