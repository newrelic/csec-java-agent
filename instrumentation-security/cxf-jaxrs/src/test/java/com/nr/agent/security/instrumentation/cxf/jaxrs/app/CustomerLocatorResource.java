package com.nr.agent.security.instrumentation.cxf.jaxrs.app;

import javax.ws.rs.Path;

@Path("/customers")
public class CustomerLocatorResource {
    protected OrdersSubResource ordersSubResource = new OrdersSubResource();

    @Path("orders")
    public Object getOrders() {
        return ordersSubResource;
    }
}
class OrdersSubResource {
    protected TestMapping idType = new TestMapping();

    @Path("getStuff")
    public Object getById() {
        return idType;
    }

}
