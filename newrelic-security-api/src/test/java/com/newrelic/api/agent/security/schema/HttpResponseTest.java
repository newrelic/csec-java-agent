package com.newrelic.api.agent.security.schema;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class HttpResponseTest {
    private final HttpResponse response = new HttpResponse();
    @Test
    public void httpRequestContentTypeNullTest() {
        response.setResponseContentType(StringUtils.EMPTY);
        Assertions.assertEquals(StringUtils.EMPTY, response.getResponseContentType());

        response.setResponseContentType("  ");
        Assertions.assertEquals(StringUtils.EMPTY, response.getResponseContentType());
    }
    @Test
    public void httpRequestContentTypeTest() {
        String contentType = "application/json";
        response.setResponseContentType(contentType);
        Assertions.assertEquals(contentType, response.getResponseContentType());

        response.setResponseContentType(contentType + ";" + contentType);
        Assertions.assertEquals(contentType, response.getResponseContentType());
    }
    @Test
    public void isEmptyTrueTest() {
        Assertions.assertTrue(response.isEmpty());

        response.setResponseBody(new StringBuilder("body"));
        Assertions.assertTrue(response.isEmpty());

        response.setResponseContentType("text/html");
        response.setResponseBody(null);
        Assertions.assertTrue(response.isEmpty());
    }
    @Test
    public void isEmptyFalseTest() {
        response.setResponseContentType("text/html");
        response.setResponseBody(new StringBuilder("body"));
        Assertions.assertFalse(response.isEmpty());
    }
}
