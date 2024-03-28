package com.nr.agent.security.instrumentation.cxf.jaxrs.app;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;

@Path("users")
public class TestMapping {
    @PUT
    public String putIt() {
        return "Put it!";
    }

    @POST
    public String postIt() {
        return "Post it!";
    }

    @GET
    public String getIt() {
        return "Get it!";
    }

    @Path("count")
    @GET
    public String pathIt() {
        return "path it!";
    }
}


