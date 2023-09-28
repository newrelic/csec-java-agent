/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.glassfish3;

import java.io.IOException;

import javax.servlet.AsyncEvent;
import javax.servlet.AsyncListener;

public final class AsyncListenerFactory {

    private AsyncListenerFactory() {
    }

    private static final AsyncListener ASYNC_LISTENER = new AsyncListener() {

        @Override
        public void onComplete(AsyncEvent asyncEvent) throws IOException {

        }

        @Override
        public void onTimeout(AsyncEvent asyncEvent) throws IOException {
            // do nothing
        }

        @Override
        public void onError(AsyncEvent asyncEvent) throws IOException {

        }

        @Override
        public void onStartAsync(AsyncEvent asyncEvent) throws IOException {
            // do nothing
        }

    };

    public static AsyncListener getAsyncListener() {
        return ASYNC_LISTENER;
    }
}
