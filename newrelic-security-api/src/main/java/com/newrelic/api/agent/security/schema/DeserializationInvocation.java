package com.newrelic.api.agent.security.schema;

import java.util.HashMap;
import java.util.Map;
import java.util.Stack;

public class DeserializationInvocation {

    private Boolean active;

    private String eid;

    private Stack<String> readObjectInAction;

    private Map<String, Serializable> encounteredSerializable;

    public DeserializationInvocation(boolean active, String executionId) {
        this.active = active;
        this.eid = executionId;
        this.readObjectInAction = new Stack<>();
        encounteredSerializable = new HashMap<>();
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public String getEid() {
        return eid;
    }

    public void setEid(String eid) {
        this.eid = eid;
    }

    public Map<String, Serializable> getEncounteredSerializable() {
        return encounteredSerializable;
    }

    public void setEncounteredSerializable(Map<String, Serializable> encounteredSerializable) {
        this.encounteredSerializable = encounteredSerializable;
    }

    public Serializable addEncounteredSerializable(Serializable serializable) {
        return this.encounteredSerializable.put(serializable.getNameOfClass(), serializable);
    }

    public Serializable getEncounteredSerializableByName(String nameOfClass) {
        return this.encounteredSerializable.get(nameOfClass);
    }

    public Stack<String> getReadObjectInAction() {
        return readObjectInAction;
    }

    public void setReadObjectInAction(Stack<String> readObjectInAction) {
        this.readObjectInAction = readObjectInAction;
    }

    public void pushReadObjectInAction(String readObjectInAction) {
        this.readObjectInAction.push(readObjectInAction);
    }

    public String popReadObjectInAction() {
        return this.readObjectInAction.pop();
    }

    public String peekReadObjectInAction() {
        if(this.readObjectInAction.isEmpty()) {
            return null;
        }
        return this.readObjectInAction.peek();
    }
}
