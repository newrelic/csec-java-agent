/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.jersey2.resources;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.Suspended;

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

