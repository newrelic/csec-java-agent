package com.nr.agent.security.instrumentation.javax.ws.rs.api.app;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

public class IdSubResource {


    @GET
    @Path("{id}")
    @Produces("application/json")
    public String getById(@PathParam("id") int id) {
        return "one";
    }

}
