package com.newrelic.api.agent.security.schema;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class HttpRequestTest {
    private final HttpRequest request = new HttpRequest();
    @Test
    public void httpRequestContentTypeNullTest() {
        request.setContentType(StringUtils.EMPTY);
        Assertions.assertEquals(StringUtils.EMPTY, request.getContentType());

        request.setContentType("  ");
        Assertions.assertEquals(StringUtils.EMPTY, request.getContentType());
    }
    @Test
    public void httpRequestContentTypeTest() {
        String contentType = "application/json";
        request.setContentType(contentType);
        Assertions.assertEquals(contentType, request.getContentType());

        request.setContentType(contentType + ";" + contentType);
        Assertions.assertEquals(contentType, request.getContentType());
    }
    @Test
    public void isEmptyTrueTest() {
        Assertions.assertTrue(request.isEmpty());

        request.setUrl("url");
        Assertions.assertTrue(request.isEmpty());

        request.setMethod("get");
        request.setUrl(StringUtils.EMPTY);
        Assertions.assertTrue(request.isEmpty());
    }
    @Test
    public void isEmptyFalseTest() {
        request.setMethod("get");
        request.setUrl("url");
        Assertions.assertFalse(request.isEmpty());
    }
}
