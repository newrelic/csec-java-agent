/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.security.introspec.HttpTestServer;
import org.junit.rules.ExternalResource;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

public class HttpServerRule extends ExternalResource implements HttpTestServer {
    private HttpTestServer server;

    @Override
    protected void before() throws Throwable {
        server = new HttpTestServerImpl();
    }

    @Override
    protected void after() {
        server.shutdown();
    }

    @Override
    public void shutdown() {
        try {
            // to prevent socket.io: broken pipe error for async calls
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        server.shutdown();
    }

    @Override
    public URI getEndPoint() throws URISyntaxException {
        return server.getEndPoint();
    }

    @Override
    public String getServerTransactionName() {
        return server.getServerTransactionName();
    }

    @Override
    public String getCrossProcessId() {
        return server.getCrossProcessId();
    }

    @Override
    public Map<String, String> getHeaders() {
        return server.getHeaders();
    }

    @Override
    public void close() throws IOException {
        server.close();
    }
}
