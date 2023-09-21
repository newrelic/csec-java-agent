package com.newrelic.agent.security.instrumentation.javax.ws.rs.api.app;

import javax.ws.rs.Path;

@Path("/customers")
public class CustomerLocatorResource {

    protected OrdersSubResource ordersSubResource = new OrdersSubResource();

    @Path("orders")
    public Object getOrders() {
        return ordersSubResource;
    }


}

