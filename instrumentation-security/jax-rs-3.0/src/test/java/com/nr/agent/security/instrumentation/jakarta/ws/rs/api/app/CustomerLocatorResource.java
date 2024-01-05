package com.nr.agent.security.instrumentation.jakarta.ws.rs.api.app;

import jakarta.ws.rs.Path;


@Path("/customers")
public class CustomerLocatorResource {

    protected OrdersSubResource ordersSubResource = new OrdersSubResource();

    @Path("orders")
    public Object getOrders() {
        return ordersSubResource;
    }


}
