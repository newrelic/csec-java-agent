package com.newrelic.agent.security.instrumentation.jakarta.ws.rs.api.app;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;


public class IdSubResource {

    @GET
    @Path("{id}")
    @Produces("application/json")
    public String getById(@PathParam("id") int id) {
        return "one";
    }

    @POST
    @Path("post")
    @Produces("application/json")
    public String getpost() {
        return "post";
    }

    @PUT
    @Path("put")
    @Produces("application/json")
    public String getput() {
        return "put";
    }

    @DELETE
    @Path("delete")
    @Produces("application/json")
    public String getdelete() {
        return "delete";
    }

    @HEAD
    @Path("head")
    @Produces("application/json")
    public String gethead() {
        return "head";
    }

    @OPTIONS
    @Path("options")
    @Produces("application/json")
    public String getoptions() {
        return "options";
    }

    @PATCH
    @Path("patch")
    @Produces("application/json")
    public String getpatch() {
        return "patch";
    }

}
