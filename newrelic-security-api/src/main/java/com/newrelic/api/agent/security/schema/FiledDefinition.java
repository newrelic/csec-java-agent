package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;

import java.util.List;

public class FiledDefinition {

    private String name;

    private String type;

    @JsonIgnore
    private List<String> parameterizedType;

    @JsonIgnore
    private boolean isPrimitive;

    private boolean isTransient;

    @JsonIgnore
    private boolean isSerializable;

    private SerializableClassDefinition classDefinition;

    public FiledDefinition() {
    }

    public FiledDefinition(String name, String type, boolean isPrimitive, boolean isTransient, boolean isSerializable) {
        this.name = name;
        this.type = type;
        this.isPrimitive = isPrimitive;
        this.isTransient = isTransient;
        this.isSerializable = isSerializable;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public boolean getIsPrimitive() {
        return isPrimitive;
    }

    public void setIsPrimitive(boolean primitive) {
        isPrimitive = primitive;
    }

    public boolean getIsTransient() {
        return isTransient;
    }

    public void setIsTransient(boolean aTransient) {
        isTransient = aTransient;
    }

    public boolean getIsSerializable() {
        return isSerializable;
    }

    public void setIsSerializable(boolean serializable) {
        isSerializable = serializable;
    }

    public SerializableClassDefinition getClassDefinition() {
        return classDefinition;
    }

    public void setClassDefinition(SerializableClassDefinition classDefinition) {
        this.classDefinition = classDefinition;
    }

    public List<String> getParameterizedType() {
        return parameterizedType;
    }

    public void setParameterizedType(List<String> parameterizedType) {
        this.parameterizedType = parameterizedType;
    }
}
