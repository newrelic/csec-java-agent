package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.intcodeagent.models.javaagent.AgentDetail;
import com.newrelic.api.agent.security.schema.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.Collections;

public class JsonConverterTest {
    @Test
    public void toJSON() {
        try {
            Field field = JsonConverter.class.getDeclaredField("serializerSelection");
            field.setAccessible(true);
            field.set(null, "");
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
        Assert.assertEquals("\"\"", JsonConverter.toJSON(StringUtils.EMPTY));
        Assert.assertEquals("\" \"", JsonConverter.toJSON(" "));
        Assert.assertEquals("\"abc \"", JsonConverter.toJSON("abc "));
        Assert.assertEquals("1", JsonConverter.toJSON(1));
        Assert.assertEquals("1.1", JsonConverter.toJSON(1.1));
        Assert.assertEquals("1.1", JsonConverter.toJSON(1.1d));
        Assert.assertEquals("1", JsonConverter.toJSON(1L));
        Assert.assertEquals("[1,2,3]", JsonConverter.toJSON(new int[]{1,2,3}));
        Assert.assertEquals("[\"1\",\"2\",\"3\"]", JsonConverter.toJSON(new String[]{"1","2","3"}));
        Assert.assertEquals("[\"String\"]", JsonConverter.toJSON(Collections.singletonList("String")));
        Assert.assertEquals("[[\"String\"]]", JsonConverter.toJSON(Collections.singletonList(Collections.singletonList("String"))));
        Assert.assertEquals("{\"key\":\"val\"}", JsonConverter.toJSON(Collections.singletonMap("key", "val")));
        Assert.assertEquals("{\"key\":{\"key\":\"val\"}}", JsonConverter.toJSON(Collections.singletonMap( "key", Collections.singletonMap("key", "val"))));
        Assert.assertEquals("[\"String\"]", JsonConverter.toJSON(Collections.singleton("String")));
        Assert.assertEquals("{\"k2Version\":null,\"k2ICToolId\":null,\"jsonVersion\":null,\"customerId\":null,\"nodeIp\":null,\"nodeId\":null,\"nodeName\":null}", JsonConverter.toJSON(new AgentDetail()));
    }
}
