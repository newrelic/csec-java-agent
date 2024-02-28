/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.play26;

import org.junit.rules.ExternalResource;
import play.Application;
import play.inject.guice.GuiceApplicationBuilder;
import play.test.Helpers;
import play.test.TestServer;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.URL;

import static play.inject.Bindings.bind;

public class PlayApplicationServerRule extends ExternalResource {
    private TestServer server;
    private int port;

    public PlayApplicationServerRule() {
        this.port = getRandomPort();
    }

    @Override
    protected void before() throws Throwable {
        Application application = new GuiceApplicationBuilder()
                .bindings(
                    bind(SimpleJavaController.class).toSelf().eagerly(),
                    bind(SimpleScalaController.class).toSelf().eagerly(),
                    bind(SimpleJavaAction.class).toSelf().eagerly())
                .build();

        server = Helpers.testServer(port, application);
        server.start();
    }

    @Override
    protected void after() {
        server.stop();
    }

    private int getRandomPort() {
        try (ServerSocket socket = new ServerSocket(0)){
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral PORT");
        }
    }

    public URL getEndpoint(String path) throws MalformedURLException {
        return new URL("http://localhost:" + port + path);
    }
}
