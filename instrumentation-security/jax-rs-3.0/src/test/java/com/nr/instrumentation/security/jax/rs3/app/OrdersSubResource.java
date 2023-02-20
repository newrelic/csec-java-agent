package com.nr.instrumentation.security.jax.rs3.app;

import jakarta.ws.rs.Path;


public class OrdersSubResource {

    protected IdSubResource idType = new IdSubResource();

    @Path("getStuff")
    public Object getById() {
        return idType;
    }

}

