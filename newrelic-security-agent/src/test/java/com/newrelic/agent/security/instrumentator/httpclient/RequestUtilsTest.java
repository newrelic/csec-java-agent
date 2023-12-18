package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.intcodeagent.models.FuzzRequestBean;
import okhttp3.MediaType;
import okhttp3.Request;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class RequestUtilsTest {
    private final String scheme = "http";
    private final String url = "/url";
    private final String get = "get";
    private final String post = "post";
    private final String EMPTY = "";
    private final int port = 8080;

    @Test
    public void generateK2RequestTest() {
        // without protocol, url, serverPort & due to this the k2-request is null
        FuzzRequestBean httpReq = Mockito.mock(FuzzRequestBean.class);

        assertNull(RequestUtils.generateK2Request(httpReq));
        Mockito.verify(httpReq).getProtocol();
        Mockito.verify(httpReq).getUrl();
        Mockito.verify(httpReq).getServerPort();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getContentType();

        Mockito.clearInvocations(httpReq);
        Mockito.clearAllCaches();
    }
    @Test
    public void generateK2RequestGet1Test() {
        // get method without body
        FuzzRequestBean httpReq = Mockito.mock(FuzzRequestBean.class);
        Mockito.doReturn(scheme).when(httpReq).getProtocol();
        Mockito.doReturn(get).when(httpReq).getMethod();
        Mockito.doReturn(url).when(httpReq).getUrl();
        Mockito.doReturn(port).when(httpReq).getServerPort();

        assertion(RequestUtils.generateK2Request(httpReq), url, get, scheme, 0, EMPTY);

        Mockito.verify(httpReq).getProtocol();
        Mockito.verify(httpReq).getUrl();
        Mockito.verify(httpReq).getServerPort();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getMethod();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getContentType();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getHeaders();

        Mockito.clearInvocations(httpReq);
        Mockito.clearAllCaches();
    }
    @Test
    public void generateK2RequestGet2Test() {
        // get method with body
        StringBuilder body = new StringBuilder("body");
        FuzzRequestBean httpReq = Mockito.mock(FuzzRequestBean.class);
        Mockito.doReturn(scheme).when(httpReq).getProtocol();
        Mockito.doReturn(get).when(httpReq).getMethod();
        Mockito.doReturn(url).when(httpReq).getUrl();
        Mockito.doReturn(port).when(httpReq).getServerPort();
        Mockito.doReturn(body).when(httpReq).getBody();

        assertion(RequestUtils.generateK2Request(httpReq), url, get, scheme, 0, EMPTY);

        Mockito.verify(httpReq).getProtocol();
        Mockito.verify(httpReq).getUrl();
        Mockito.verify(httpReq).getServerPort();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getMethod();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getContentType();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getHeaders();

        Mockito.clearInvocations(httpReq);
        Mockito.clearAllCaches();
    }
    @Test
    public void generateK2RequestPost1Test() {
        // without body & content-type
        FuzzRequestBean httpReq = Mockito.mock(FuzzRequestBean.class);
        Mockito.doReturn(scheme).when(httpReq).getProtocol();
        Mockito.doReturn(post).when(httpReq).getMethod();
        Mockito.doReturn(url).when(httpReq).getUrl();
        Mockito.doReturn(port).when(httpReq).getServerPort();
        Mockito.doReturn(new StringBuilder("body")).when(httpReq).getBody();

        assertion(RequestUtils.generateK2Request(httpReq), url, post, scheme, 4, EMPTY);

        Mockito.verify(httpReq).getProtocol();
        Mockito.verify(httpReq).getUrl();
        Mockito.verify(httpReq).getServerPort();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getMethod();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getContentType();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getHeaders();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getBody();

        Mockito.clearInvocations(httpReq);
        Mockito.clearAllCaches();
    }
    @Test
    public void generateK2RequestPost2Test() {
        // with body but without content-type
        StringBuilder body = new StringBuilder("body");
        FuzzRequestBean httpReq = Mockito.mock(FuzzRequestBean.class);
        Mockito.doReturn(scheme).when(httpReq).getProtocol();
        Mockito.doReturn(post).when(httpReq).getMethod();
        Mockito.doReturn(url).when(httpReq).getUrl();
        Mockito.doReturn(port).when(httpReq).getServerPort();
        Mockito.doReturn(body).when(httpReq).getBody();


        assertion(RequestUtils.generateK2Request(httpReq), url, post, scheme, body.length(), EMPTY);

        Mockito.verify(httpReq).getProtocol();
        Mockito.verify(httpReq).getUrl();
        Mockito.verify(httpReq).getServerPort();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getMethod();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getContentType();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getHeaders();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getBody();

        Mockito.clearInvocations(httpReq);
        Mockito.clearAllCaches();
    }

    @Test
    public void generateK2RequestPost3Test() {
        // with body & content-type

        StringBuilder body = new StringBuilder("{\"key\":\"body\"}");
        String contentType = "application/json; charset=utf-8";
        FuzzRequestBean httpReq = Mockito.mock(FuzzRequestBean.class);
        Mockito.doReturn(scheme).when(httpReq).getProtocol();
        Mockito.doReturn(post).when(httpReq).getMethod();
        Mockito.doReturn(url).when(httpReq).getUrl();
        Mockito.doReturn(port).when(httpReq).getServerPort();
        Mockito.doReturn(body).when(httpReq).getBody();
        Mockito.doReturn(contentType).when(httpReq).getContentType();

        assertion(RequestUtils.generateK2Request(httpReq), url, post, scheme, body.length(), contentType);

        Mockito.verify(httpReq).getProtocol();
        Mockito.verify(httpReq).getUrl();
        Mockito.verify(httpReq).getServerPort();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getMethod();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getContentType();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getHeaders();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getBody();

        Mockito.clearInvocations(httpReq);
        Mockito.clearAllCaches();
    }
    @Test
    public void generateK2RequestHeadersTest() {
        // with headers
        FuzzRequestBean httpReq = Mockito.mock(FuzzRequestBean.class);
        Mockito.doReturn(scheme).when(httpReq).getProtocol();
        Mockito.doReturn(get).when(httpReq).getMethod();
        Mockito.doReturn(url).when(httpReq).getUrl();
        Mockito.doReturn(port).when(httpReq).getServerPort();
        Mockito.doReturn(Collections.singletonMap("key","val")).when(httpReq).getHeaders();

        Request request = RequestUtils.generateK2Request(httpReq);
        assertion(request, url, get, scheme, 0, EMPTY);
        assertNotNull(request.headers());
        assertEquals(Collections.singletonMap("key", Collections.singletonList("val")), request.headers().toMultimap());

        Mockito.verify(httpReq).getProtocol();
        Mockito.verify(httpReq).getUrl();
        Mockito.verify(httpReq).getServerPort();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getMethod();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getContentType();
        Mockito.verify(httpReq, Mockito.atLeastOnce()).getHeaders();

        Mockito.clearInvocations(httpReq);
        Mockito.clearAllCaches();
    }

    public void assertion(Request request, String url, String method, String scheme, int contentLen, String contentType){
        assertNotNull(request);
        assertEquals(String.format("%s://localhost:%d%s", scheme, port, url), request.url().toString());
        assertEquals(scheme, request.url().scheme());
        assertEquals(method, request.method());
        if (request.body() != null){
            try {
                assertEquals(contentLen, request.body().contentLength());
                assertEquals(MediaType.parse(contentType), request.body().contentType());
            } catch (IOException e) {
                throw new RuntimeException("unable to read content-length");
            }
        }
    }
}
