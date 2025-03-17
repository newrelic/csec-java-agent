package com.newrelic.agent.security.intcodeagent.serializers;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.api.agent.security.schema.StringBuilderLimit;

import java.io.IOException;

public class StringBuilderLimitSerializer extends JsonSerializer<StringBuilderLimit> {
    @Override
    public void serialize(StringBuilderLimit stringBuilderLimit, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(stringBuilderLimit.toString());
    }
}
