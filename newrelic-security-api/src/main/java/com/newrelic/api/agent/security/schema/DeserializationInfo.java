package com.newrelic.api.agent.security.schema;

import java.util.*;


public class DeserializationInfo {

    private String type;
    private Set<DeserializationInfo> unlinkedChildren = new HashSet<>();
    private Object instance;

    public DeserializationInfo(String type, Object instance) {
        this.type = type;
        this.instance = instance;
    }

    public DeserializationInfo(DeserializationInfo instance) {
        if (instance == null) {
            return;
        }
        this.type = instance.type;
//        for(DeserializationInfo value: instance.unlinkedChildren){
//            value.computeObjectMap();
//            this.unlinkedChildren.add(new DeserializationInfo(value));
//        }
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Object getInstance() {
        return instance;
    }

    public void setInstance(Object instance) {
        this.instance = instance;
    }

    public Set<DeserializationInfo> getUnlinkedChildren() {
        return unlinkedChildren;
    }

    public void setUnlinkedChildren(Set<DeserializationInfo> unlinkedChildren) {
        this.unlinkedChildren = unlinkedChildren;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DeserializationInfo)) return false;
        DeserializationInfo that = (DeserializationInfo) o;
        return Objects.equals(type, that.type) && Objects.equals(instance, that.instance);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, instance);
    }
}