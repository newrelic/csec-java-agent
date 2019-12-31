package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class ThreadLocalHttpMap {

    private Object httpRequest;

    private boolean isHttpRequestParsed = false;

    private Object httpResponse;

    private boolean isHttpResposeParsed = false;

    private ByteBuffer byteBuffer;

    private int bufferOffset = 0;

    private static ThreadLocal<ThreadLocalHttpMap> instance =
            new ThreadLocal<ThreadLocalHttpMap>() {
                @Override
                protected ThreadLocalHttpMap initialValue() {
                    return new ThreadLocalHttpMap();
                }
            };

    private ThreadLocalHttpMap() {
        this.byteBuffer = ByteBuffer.allocate(1024 * 8);
    }

    public static ThreadLocalHttpMap getInstance() {
        return instance.get();
    }

    public Object getHttpRequest() {
        return httpRequest;
    }

    public void setHttpRequest(Object httpRequest) {
        this.httpRequest = httpRequest;
    }

    public Object getHttpResponse() {
        return httpResponse;
    }

    public void setHttpResponse(Object httpResponse) {
        this.httpResponse = httpResponse;
    }

    public boolean isHttpRequestParsed() {
        return isHttpRequestParsed;
    }

    public boolean isHttpResposeParsed() {
        return isHttpResposeParsed;
    }

    public boolean parseHttpRequest() {
        if (httpRequest == null) {
            System.out.println("No HTTP request found for current context");
            return false;
        }

        if (isHttpRequestParsed) {
            System.out.println("HTTP request already parsed for current context");
            updateBody();
            return true;
        }
        HttpRequestBean httpRequestBean = ThreadLocalExecutionMap.getInstance().getHttpRequestBean();
        AgentMetaData metaData = ThreadLocalExecutionMap.getInstance().getMetaData();
        try {
            Class requestClass = httpRequest.getClass();

            Method getMethod = requestClass.getMethod("getMethod");
            getMethod.setAccessible(true);
            httpRequestBean.setMethod((String) getMethod.invoke(httpRequest, null));

            Method getRemoteAddr = requestClass.getMethod("getRemoteAddr");
            getRemoteAddr.setAccessible(true);
            httpRequestBean.setClientIP((String) getRemoteAddr.invoke(httpRequest, null));

            Map<String, String> headers = new HashMap<>();
            processHeaders(headers, httpRequest);
            httpRequestBean.setHeaders(new JSONObject(headers));

            Method getRequestURI = requestClass.getMethod("getRequestURI");
            getRequestURI.setAccessible(true);
            httpRequestBean.setUrl((String) getRequestURI.invoke(httpRequest, null));

            Method getServletContext = requestClass.getMethod("getServletContext");
            getServletContext.setAccessible(true);
            Object servletContext = getServletContext.invoke(httpRequest, null);

            Method getContextPath = servletContext.getClass().getMethod("getContextPath");
            getContextPath.setAccessible(true);
            String contextPath = (String) getContextPath.invoke(servletContext, null);
            httpRequestBean.setContextPath(contextPath);
            ServletContextInfo.getInstance().processServletContext(servletContext, contextPath);
            updateBody();
            isHttpRequestParsed = true;
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.out.println("RAW Intercepted Request : " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean());
        }
        return false;
    }


    public boolean parseHttpResponse() {
        // TODO : To be implemented
        if (httpRequest == null) {
            System.out.println("No HTTP request found for current context");
            return false;
        }

        if (!isHttpRequestParsed) {
            System.out.println("HTTP request already parsed for current context");
            updateBody();
            return true;
        }

        return false;
    }

    public void processHeaders(Map<String, String> headers, Object httpRequest) {
        try {
            Class requestClass = httpRequest.getClass();

            Method getHeaderNames = requestClass.getMethod("getHeaderNames", null);
            Method getHeaders = requestClass.getMethod("getHeaders", String.class);

            Enumeration<String> attribs = ((Enumeration<String>) getHeaderNames.invoke(httpRequest, null));
            while (attribs.hasMoreElements()) {
                String headerKey = attribs.nextElement();
                String headerFullValue = StringUtils.EMPTY;
                Enumeration<String> headerElements = (Enumeration<String>) getHeaders.invoke(httpRequest, headerKey);
                while (headerElements.hasMoreElements()) {
                    String headerValue = headerElements.nextElement();
                    if (headerFullValue.isEmpty()) {
                        headerFullValue = headerValue;
                    } else {
                        headerFullValue += "; " + headerValue;
                    }
                }
                headers.put(headerKey, headerFullValue);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void insertToRequestByteBuffer(byte b) {
        try {
            byteBuffer.put(b);
//            System.out.println("inserting : " + b);
        } catch (Exception e) {
            e.printStackTrace();
            // Buffer full. discard data.
        }
    }

    public void insertToRequestByteBuffer(byte[] b) {
        try {
            byteBuffer.put(b);
//            System.out.println("inserting : " + Arrays.asList(b));
        } catch (Exception e) {
            e.printStackTrace();
            // Buffer full. discard data.
        }
    }


    public void updateBody() {
        try {
            if (byteBuffer.position() > bufferOffset) {
                String oldBody = ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getBody();
                ThreadLocalExecutionMap.getInstance().getHttpRequestBean().setBody(oldBody + new String(byteBuffer.array(), bufferOffset, byteBuffer.position()));
                bufferOffset = byteBuffer.position();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void cleanState(){
        httpRequest = null;
        isHttpRequestParsed = false;
        httpResponse = null;
        isHttpResposeParsed = false;
        bufferOffset = 0;
        byteBuffer = ByteBuffer.allocate(1024 * 8);
    }
}
