/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.jersey2.resources;

import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.container.AsyncResponse;
import jakarta.ws.rs.container.Suspended;

@Path("/operation")
public class Resource {
    @GET
    @Path("/sync")
    public String syncEndpoint(@DefaultValue("param") @QueryParam("param") final String param) {
        return "sync result";
    }

    @GET
    @Path("/async")
    public void resume(@DefaultValue("1") @QueryParam("sleep") final int sleepMillis, @Suspended final AsyncResponse response) {
        response.resume("async result");
    }
}

