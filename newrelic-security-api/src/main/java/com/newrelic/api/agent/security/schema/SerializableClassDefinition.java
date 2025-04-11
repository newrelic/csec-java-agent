package com.newrelic.api.agent.security.schema;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class SerializableClassDefinition {

    private String name;

    private boolean isInterface;

    private List<FiledDefinition> fields;

    public SerializableClassDefinition(String name, boolean anInterface, List<FiledDefinition> filedDefinitions) {
        this.isInterface = anInterface;
        this.name = name;
        this.fields = filedDefinitions;
    }


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<FiledDefinition> getFields() {
        return fields;
    }

    public void setFields(List<FiledDefinition> fields) {
        this.fields = fields;
    }

    public boolean addFields(FiledDefinition field) {
        return this.fields.add(field);
    }

    public boolean getIsInterface() {
        return isInterface;
    }

    public void setIsInterface(boolean isInterface) {
        this.isInterface = isInterface;
    }

}
