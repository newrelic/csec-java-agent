package com.newrelic.api.agent.security.instrumentation.helpers;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

public class GrpcHelperTest {

    @Test
    public void testGetFormattedIp() {
        Assertions.assertEquals("197.0.0.1", GrpcHelper.getFormattedIp("197.0.0.1"));
        Assertions.assertEquals("0:0:0:0:0:0:0:1", GrpcHelper.getFormattedIp("0:0:0:0:0:0:0:1"));
        Assertions.assertEquals("", GrpcHelper.getFormattedIp("gibberish"));
    }

    @Test
    public void testGetPort() {
        Assertions.assertEquals("8080", GrpcHelper.getPort("197.0.0.1:8080"));
        Assertions.assertEquals("8080", GrpcHelper.getPort("http://localhost:8080"));
        Assertions.assertEquals("443", GrpcHelper.getPort("https://localhost:443"));
    }

    public static void clearMockitoInvocation(MockedStatic<?> ... mockedStatic) {
        try {
        } finally {
            for (MockedStatic<?> aStatic : mockedStatic) {
                aStatic.reset();
                aStatic.clearInvocations();
                aStatic.close();
            }
        }
    }

}
