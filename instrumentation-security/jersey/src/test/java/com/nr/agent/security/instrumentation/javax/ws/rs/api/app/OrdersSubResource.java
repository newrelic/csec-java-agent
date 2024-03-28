package com.nr.agent.security.instrumentation.javax.ws.rs.api.app;

import javax.ws.rs.Path;

public class OrdersSubResource {

    protected IdSubResource idType = new IdSubResource();

    @Path("getStuff")
    public Object getById() {
        return idType;
    }

}
