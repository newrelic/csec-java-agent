/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.security.introspec.HttpTestServer;

import java.io.IOException;

public class HttpServerLocator {
    public static HttpTestServer createAndStart() throws IOException {
        return new HttpTestServerImpl();
    }
}
