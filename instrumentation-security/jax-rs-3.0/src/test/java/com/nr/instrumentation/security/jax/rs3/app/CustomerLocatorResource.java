package com.nr.instrumentation.security.jax.rs3.app;

import jakarta.ws.rs.Path;


@Path("/customers")
public class CustomerLocatorResource {

    protected OrdersSubResource ordersSubResource = new OrdersSubResource();

    @Path("orders")
    public Object getOrders() {
        return ordersSubResource;
    }


}
