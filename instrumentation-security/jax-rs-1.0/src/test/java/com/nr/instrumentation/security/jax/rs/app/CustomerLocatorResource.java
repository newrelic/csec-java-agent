package com.nr.instrumentation.security.jax.rs.app;

import javax.ws.rs.Path;

@Path("/customers")
public class CustomerLocatorResource {

    protected OrdersSubResource ordersSubResource = new OrdersSubResource();

    @Path("orders")
    public Object getOrders() {
        return ordersSubResource;
    }


}

