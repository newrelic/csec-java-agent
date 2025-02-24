package com.newrelic.api.agent.security.schema;

import java.util.ArrayList;
import java.util.List;


public class DeserializationInfo {

    private String type;
    private List<DeserializationInfo> unlinkedChildren = new ArrayList<>();
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

    public List<DeserializationInfo> getUnlinkedChildren() {
        return unlinkedChildren;
    }

    public void setUnlinkedChildren(List<DeserializationInfo> unlinkedChildren) {
        this.unlinkedChildren = unlinkedChildren;
    }
}