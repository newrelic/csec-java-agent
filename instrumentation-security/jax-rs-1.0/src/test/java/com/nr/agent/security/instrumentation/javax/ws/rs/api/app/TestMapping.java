package com.nr.agent.security.instrumentation.javax.ws.rs.api.app;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HEAD;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.PATCH;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;

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


