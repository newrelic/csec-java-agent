package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class ThreadLocalHttpMap {

    private Object httpRequest;

    private boolean isHttpRequestParsed = false;

    private Object httpResponse;

    private boolean isHttpResposeParsed = true;


    private static ThreadLocal<ThreadLocalHttpMap> instance =
            new ThreadLocal<ThreadLocalHttpMap>() {
                @Override
                protected ThreadLocalHttpMap initialValue() {
                    return new ThreadLocalHttpMap();
                }
            };

    private ThreadLocalHttpMap() {
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

    public void parseHttpRequest() {
        if (httpRequest == null) {
            System.out.println("No HTTP request found for current context");
            return;
        }
        HttpRequestBean httpRequestBean = ThreadLocalExecutionMap.getInstance().getHttpRequestBean();
        AgentMetaData metaData = ThreadLocalExecutionMap.getInstance().getMetaData();
        try {
            Class requestClass = httpRequest.getClass();

            Method getMethod = requestClass.getMethod("getMethod");
            httpRequestBean.setMethod((String) getMethod.invoke(httpRequest, null));

            Method getRemoteAddr = requestClass.getMethod("getRemoteAddr");
            httpRequestBean.setClientIP((String) getRemoteAddr.invoke(httpRequest, null));

            Map<String, String> headers = new HashMap<>();
            processHeaders(headers, httpRequest);
            httpRequestBean.setHeaders(new JSONObject(headers));

            Method getRequestURI = requestClass.getMethod("getRequestURI");
            httpRequestBean.setUrl((String) getRequestURI.invoke(httpRequest, null));

            Method getServletContext = requestClass.getMethod("getServletContext");
            Object servletContext = getServletContext.invoke(httpRequest, null);

            Method getContextPath = servletContext.getClass().getMethod("getContextPath");
            String contextPath = (String) getContextPath.invoke(servletContext, null);
            httpRequestBean.setContextPath(contextPath);
            ServletContextInfo.getInstance().processServletContext(servletContext, contextPath);
            httpRequestBean.updateBody();
            isHttpRequestParsed = true;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
//            ThreadLocalExecutionMap.getInstance().setHttpRequestBean(new HttpRequestBean(httpRequestBean));
//            ThreadLocalExecutionMap.getInstance().setMetaData(new AgentMetaData(metaData));
            System.out.println("Intercepted Request : " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean());
        }
    }


    public void parseHttpResponse() {
        // TODO : To be implemented
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
        ThreadLocalExecutionMap.getInstance().getHttpRequestBean().insertToByteBuffer(b);
    }

    public void insertToRequestByteBuffer(byte[] b) {
        ThreadLocalExecutionMap.getInstance().getHttpRequestBean().insertToByteBuffer(b);
    }
}
