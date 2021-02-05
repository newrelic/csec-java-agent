package com.k2cybersecurity.intcodeagent.models.javaagent;

public enum OutBoundHttpDirection {

    INBOUND("INBOUND"),
    OUTBOUND("OUTBOUND");

    private String direction;

    OutBoundHttpDirection(String direction) {
        this.direction = direction;
    }

    public String getDirection() {
        return direction;
    }

    public void setDirection(String direction) {
        this.direction = direction;
    }

    @Override
    public String toString() {
        return this.direction;
    }
}
