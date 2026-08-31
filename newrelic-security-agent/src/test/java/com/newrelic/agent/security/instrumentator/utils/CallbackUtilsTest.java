package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class CallbackUtilsTest {

    @Test
    public void checkForReflectedXSSTest() {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(new HttpRequest(), new HttpResponse()));
    }

    @Test
    public void checkForReflectedXSS1Test() {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(new HttpRequest(), new HttpResponse()));
    }

    @Test
    public void checkForReflectedXSS2Test() {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(new HttpRequest(), new HttpResponse()));
    }

    @Test
    public void checkForReflectedXSS3Test() {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        HttpRequest request = new HttpRequest(); request.getHeaders().put("key","%3Cscript%3Ehello%3C%2Fscript%3E");
        request.setContentType("application/x-www-form-urlencoded");
        request.getBody().append("script%3D%3Cscript%3Ehello%3C%2Fscript%3E");

        HttpResponse response = new HttpResponse(); response.getHeaders().put("key","%3Cscript%3Ehello%3C%2Fscript%3E");
        response.setResponseContentType("application/x-www-form-urlencoded");
        response.getResponseBody().append("script%3D%3Cscript%3Ehello%3C%2Fscript%3E");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(request, response));
    }

    @Test
    public void checkForReflectedXSS_BodyJsonTest() {
        HttpRequest request = new HttpRequest(); request.getHeaders().put("key","%3Cscript%3Ehello%3C%2Fscript%3E");
        request.setContentType("application/json");
        request.getBody().append("{\"script\":\"<script>hello</script>\"}");

        HttpResponse response = new HttpResponse(); response.getHeaders().put("key","%3Cscript%3Ehello%3C%2Fscript%3E");
        response.setResponseContentType("application/xml");
        response.getResponseBody().append("{\"script\":\"<script>hello</script>\"}");
        Assert.assertEquals(Collections.singleton("<script>hello"), CallbackUtils.checkForReflectedXSS(request, response));
    }

    @Test
    public void checkForReflectedXSS_BodyXMLTest() {
        HttpRequest request = new HttpRequest(); request.getHeaders().put("key","%3Cscript%3Ehello%3C%2Fscript%3E");
        request.setContentType("application/xml");
        request.getBody().append("<code>'\\''<script>hello</script>'\\''</code>");

        HttpResponse response = new HttpResponse(); response.getHeaders().put("key","%3Cscript%3Ehello%3C%2Fscript%3E");
        response.setResponseContentType("application/xml");
        response.getResponseBody().append("<code>'\\''<script>hello</script>'\\''</code>");
        Assert.assertEquals(Collections.singleton("<script>hello"), CallbackUtils.checkForReflectedXSS(request, response));
    }

    @Test
    public void urlDecodeTest() {
        Assert.assertEquals(StringUtils.EMPTY, CallbackUtils.urlDecode(StringUtils.EMPTY));
        Assert.assertEquals("  ", CallbackUtils.urlDecode("  "));
        Assert.assertEquals("<script>", CallbackUtils.urlDecode("<script>"));
        Assert.assertEquals("<script>", CallbackUtils.urlDecode("%3Cscript%3E"));
    }

    @Test
    public void urlEncodeTest() {
        Assert.assertEquals(StringUtils.EMPTY, CallbackUtils.urlEncode(StringUtils.EMPTY));
        Assert.assertEquals("++", CallbackUtils.urlEncode("  "));
        Assert.assertEquals("%3Cscript%3E", CallbackUtils.urlEncode("<script>"));
        Assert.assertEquals("u%3D%3Cscript%3E", CallbackUtils.urlEncode("u=<script>"));
    }

    @Test
    public void getXSSConstructsTest() {
        Set<String> actual = CallbackUtils.getXSSConstructs("<script>some</script>");
        Set<String> expected = new HashSet<>();
        expected.add("<script>some");
        Assert.assertNotNull(actual);
        Assert.assertEquals(1, actual.size());
        Assert.assertEquals(expected, actual);
    }

    @Test
    public void getXSSConstructs1Test() {
        Set<String> actual = CallbackUtils.getXSSConstructs("<script>alert(1)</script>");
        Set<String> expected = new HashSet<>();
        expected.add("<script>alert(1)");
        Assert.assertNotNull(actual);
        Assert.assertEquals(1, actual.size());
        Assert.assertEquals(expected, actual);
    }
}
