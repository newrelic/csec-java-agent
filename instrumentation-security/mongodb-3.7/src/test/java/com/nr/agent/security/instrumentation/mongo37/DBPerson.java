package com.nr.agent.security.instrumentation.mongo37;

import org.bson.Document;

public class DBPerson extends Document {
    private String name;
    private String type;
    private int count;

    public DBPerson(String name, String type, int count) {
        this.name = name;
        this.type = type;
        this.count = count;
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

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }
}
