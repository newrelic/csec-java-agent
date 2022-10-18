package com.k2cybersecurity.intcodeagent.deserializers;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;

import java.io.IOException;
import java.util.List;

public class K2StackTraceSerializer extends JsonSerializer<List<StackTraceElement>> {

    @Override
    public void serialize(List<StackTraceElement> stackTraceElements, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartArray();
        for (StackTraceElement stackTraceElement : stackTraceElements) {
            jsonGenerator.writeString(AgentUtils.stackTraceElementToString(stackTraceElement));
        }
        jsonGenerator.writeEndArray();
    }
}
