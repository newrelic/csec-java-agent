package com.nr.instrumentation.resteasy2_2.app;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;

@Path("users")
public class TestMapping {
    @GET
    public String getIt() {
        return "Get it!";
    }

    @Path("count")
    @GET
    @Consumes("application/json")
    public String pathIt() {
        return "path it!";
    }
}


