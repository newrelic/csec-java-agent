package com.nr.agent.security.instrumentation.mongo38.operation;

import org.bson.BsonReader;
import org.bson.BsonWriter;
import org.bson.codecs.Codec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.EncoderContext;

public class DBPersonCodec implements Codec<DBPerson> {
    @Override
    public void encode(BsonWriter writer, DBPerson value, EncoderContext encoderContext) {
        writer.writeStartDocument();
        writer.writeString("name", value.getName());
        writer.writeString("type", value.getType());
        writer.writeInt32("count", value.getCount());
        writer.writeEndDocument();
    }

    @Override
    public DBPerson decode(BsonReader reader, DecoderContext decoderContext) {
        reader.readStartDocument();
        String name = reader.readString("name");
        String type = reader.readString("type");
        int count = reader.readInt32("count");
        reader.readEndDocument();
        return new DBPerson(name, type, count);
    }

    @Override
    public Class<DBPerson> getEncoderClass() {
        return DBPerson.class;
    }
}