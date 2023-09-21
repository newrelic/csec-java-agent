package com.newrelic.agent.security.instrumentation.jakarta.ws.rs.api.app;

import jakarta.ws.rs.Path;


public class OrdersSubResource {

    protected IdSubResource idType = new IdSubResource();

    @Path("getStuff")
    public Object getById() {
        return idType;
    }

}

