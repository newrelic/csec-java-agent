package com.nr.agent.security.instrumentation.javax.ws.rs.api.app;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HEAD;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.PATCH;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
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
