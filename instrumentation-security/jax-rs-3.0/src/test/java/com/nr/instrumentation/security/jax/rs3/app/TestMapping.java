package com.nr.instrumentation.security.jax.rs3.app;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;


@Path("users")
public class TestMapping {
    @PUT
    @Consumes("application/json")
    public String putIt() {
        return "Put it!";
    }

    @POST
    @Consumes("application/json")
    public String postIt() {
        return "Post it!";
    }

    @GET
    @Consumes("application/json")
    public String getIt() {
        return "Get it!";
    }

    @DELETE
    @Consumes("application/json")
    public String deleteIt() {
        return "Delete it!";
    }

    @HEAD
    @Consumes("application/json")
    public String headIt() {
        return "Head it!";
    }

    @OPTIONS
    @Consumes("application/json")
    public String optionsIt() {
        return "Options it!";
    }

    @PATCH
    @Consumes("application/json")
    public String patchIt() {
        return "Patch it!";
    }

    @Path("count")
    @Consumes("application/json")
    public String pathIt() {
        return "path it!";
    }

}
