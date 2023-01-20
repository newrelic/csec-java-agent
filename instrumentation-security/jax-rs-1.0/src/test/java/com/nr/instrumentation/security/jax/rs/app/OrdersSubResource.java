package com.nr.instrumentation.security.jax.rs.app;

import javax.ws.rs.Path;

public class OrdersSubResource {

    protected IdSubResource idType = new IdSubResource();

    @Path("getStuff")
    public Object getById() {
        return idType;
    }

}
