package com.newrelic.agent.security.intcodeagent.serializers;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;

import java.io.IOException;

public class K2StackTraceSerializer extends JsonSerializer<StackTraceElement> {

    @Override
    public void serialize(StackTraceElement stackTraceElement, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(AgentUtils.stackTraceElementToString(stackTraceElement));
    }
}
