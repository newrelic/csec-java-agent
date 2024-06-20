/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package io.vertx.core.http.impl;

import com.newrelic.agent.security.instrumentation.vertx.web.VertxClientHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;


@Weave(originalName = "io.vertx.core.http.impl.HttpClientRequestImpl")
public abstract class HttpClientRequestImpl_Instrumentation {

    public abstract MultiMap headers();

    public abstract String absoluteURI();

    public void end(Buffer chunk) {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = VertxClientHelper.preprocessSecurityHook(absoluteURI(), this.getClass().getName(),
                    VertxClientHelper.METHOD_END);
            VertxClientHelper.addSecurityHeaders(headers(), operation);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        VertxClientHelper.registerExitOperation(isLockAcquired, operation);
    }

    public void end(Buffer chunk, Handler<AsyncResult<Void>> handler) {

        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = VertxClientHelper.preprocessSecurityHook(absoluteURI(), this.getClass().getName(),
                    VertxClientHelper.METHOD_END);
            VertxClientHelper.addSecurityHeaders(headers(), operation);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        VertxClientHelper.registerExitOperation(isLockAcquired, operation);
    }

    public void end() {

        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = VertxClientHelper.preprocessSecurityHook(absoluteURI(), this.getClass().getName(),
                    VertxClientHelper.METHOD_END);
            VertxClientHelper.addSecurityHeaders(headers(), operation);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        VertxClientHelper.registerExitOperation(isLockAcquired, operation);
    }

    public void end(Handler<AsyncResult<Void>> handler) {

        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = VertxClientHelper.preprocessSecurityHook(absoluteURI(), this.getClass().getName(),
                    VertxClientHelper.METHOD_END);
            VertxClientHelper.addSecurityHeaders(headers(), operation);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        VertxClientHelper.registerExitOperation(isLockAcquired, operation);
    }
    private void releaseLock() {
        GenericHelper.releaseLock(VertxClientHelper.getNrSecCustomAttribName());
    }

    private boolean acquireLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VertxClientHelper.getNrSecCustomAttribName());
    }
}
