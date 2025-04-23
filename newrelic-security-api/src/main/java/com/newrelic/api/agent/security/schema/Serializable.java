package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;

import java.util.Objects;

public class Serializable {

    private String nameOfClass;

    @JsonIgnore
    private Class<?> klass;

    private Boolean deserializable;

    private SerializableClassDefinition classDefinition;

    public Serializable() {
    }

    public Serializable(String nameOfClass, Boolean deserializable) {
        this.nameOfClass = nameOfClass;
        this.deserializable = deserializable;
    }

    public String getNameOfClass() {
        return nameOfClass;
    }

    public void setNameOfClass(String nameOfClass) {
        this.nameOfClass = nameOfClass;
    }

    public Boolean getDeserializable() {
        return deserializable;
    }

    public void setDeserializable(Boolean deserializable) {
        this.deserializable = deserializable;
    }

    public SerializableClassDefinition getClassDefinition() {
        return classDefinition;
    }

    public void setClassDefinition(SerializableClassDefinition classDefinition) {
        this.classDefinition = classDefinition;
    }

    public Class<?> getKlass() {
        return klass;
    }

    public void setKlass(Class<?> klass) {
        this.klass = klass;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Serializable)) return false;
        Serializable that = (Serializable) o;
        return Objects.equals(nameOfClass, that.nameOfClass);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(nameOfClass);
    }
}
