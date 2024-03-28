package com.nr.agent.security.instrumentation.javax.ws.rs.api.app;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;

@Path("users")
    public class TestMapping {
        @PUT
        @Consumes("application/json")
        public String putIt() {
            return "Put it!";
        }


    @Path("count")
    @GET
    @Consumes("application/json")
    public String pathIt() {
        return "path it!";
    }
    }


