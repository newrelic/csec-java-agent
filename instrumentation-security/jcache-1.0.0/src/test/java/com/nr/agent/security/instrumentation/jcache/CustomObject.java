package com.nr.agent.security.instrumentation.jcache;

import com.hazelcast.nio.ObjectDataInput;
import com.hazelcast.nio.ObjectDataOutput;
import com.hazelcast.nio.serialization.DataSerializable;

import java.io.IOException;

public class CustomObject implements DataSerializable {
    String name;
    int age;

    public CustomObject() {

    }

    public CustomObject(String name, int age) {
        this.name = name;
        this.age = age;
    }

    @Override
    public void writeData(ObjectDataOutput out) throws IOException {
        out.writeUTF(name);
        out.writeInt(age);
    }

    @Override
    public void readData(ObjectDataInput in) throws IOException {
        name = in.readUTF();
        age = in.readInt();
    }
}