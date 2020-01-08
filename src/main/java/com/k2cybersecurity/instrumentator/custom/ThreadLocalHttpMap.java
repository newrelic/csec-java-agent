package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.instrumentator.AgentNew;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class ThreadLocalHttpMap {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private Object httpRequest;

    private boolean isHttpRequestParsed = false;

    private Object httpResponse;

    private Object printWriter;

    private ByteBuffer byteBuffer;

    private StringBuilder outputBodyBuilder;

    private int bufferOffset = 0;

    private boolean isHttpResponseParsed = false;


    private static ThreadLocal<ThreadLocalHttpMap> instance =
            new ThreadLocal<ThreadLocalHttpMap>() {
                @Override
                protected ThreadLocalHttpMap initialValue() {
                    return new ThreadLocalHttpMap();
                }
            };

    private ThreadLocalHttpMap() {
        this.byteBuffer = ByteBuffer.allocate(1024 * 8);
        this.outputBodyBuilder = new StringBuilder();
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

    public Object getPrintWriter() {
        return printWriter;
    }

    public void setPrintWriter(Object printWriter) {
        this.printWriter = printWriter;
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

            Method getQueryString = requestClass.getMethod("getQueryString");
            getQueryString.setAccessible(true);
            String queryString = (String) getQueryString.invoke(httpRequest, null);

            if (StringUtils.isNotBlank(queryString)) {
                httpRequestBean.setUrl(httpRequestBean.getUrl() + "?" + queryString);
            }

            Method getServletContext = requestClass.getMethod("getServletContext");
            getServletContext.setAccessible(true);
            Object servletContext = getServletContext.invoke(httpRequest, null);

            Method getContextPath = servletContext.getClass().getMethod("getContextPath");
            getContextPath.setAccessible(true);
            String contextPath = (String) getContextPath.invoke(servletContext, null);
            httpRequestBean.setContextPath(contextPath);

            Method getLocalPort = requestClass.getMethod("getServerPort");
            getLocalPort.setAccessible(true);
            int serverPort = (Integer) getLocalPort.invoke(httpRequest, null);
            httpRequestBean.setServerPort(serverPort);

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


    public void processHeaders(Map<String, String> headers, Object httpRequest) {
        try {
            Class requestClass = httpRequest.getClass();

            Method getHeaderNames = requestClass.getMethod("getHeaderNames", null);
            getHeaderNames.setAccessible(true);
            Method getHeaders = requestClass.getMethod("getHeaders", String.class);
            getHeaders.setAccessible(true);

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

    public boolean parseHttpResponse() {
        // TODO : To be implemented
        if (httpResponse == null) {
            System.out.println("No HTTP response found for current context");
            return false;
        }

        updateResponseBody();

        try {

            if (isHttpResponseParsed) {
                System.out.println("HTTP response already parsed for current context");
                return true;
            }

            HttpRequestBean httpRequestBean = ThreadLocalExecutionMap.getInstance().getHttpRequestBean();

            Class responseClass = httpResponse.getClass();

            Method getCharacterEncoding = responseClass.getMethod("getCharacterEncoding");
            getCharacterEncoding.setAccessible(true);
            httpRequestBean.getHttpResponseBean().setResponseCharacterEncoding((String) getCharacterEncoding.invoke(httpResponse, null));

            Method getContentType = responseClass.getMethod("getContentType");
            getContentType.setAccessible(true);
            httpRequestBean.getHttpResponseBean().setResponseContentType((String) getContentType.invoke(httpResponse, null));

            Map<String, String> headers = new HashMap<>();
            processResponseHeaders(headers, httpResponse);
            httpRequestBean.getHttpResponseBean().setHeaders(new JSONObject(headers));

            // TODO: based on content info, parse/decode the received reponse data here.

            isHttpResponseParsed = true;
            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public void processResponseHeaders(Map<String, String> headers, Object httpRequest) {
        try {
            Class requestClass = httpRequest.getClass();

            Method getHeaderNames = requestClass.getMethod("getHeaderNames", null);
            getHeaderNames.setAccessible(true);
            Method getHeaders = requestClass.getMethod("getHeaders", String.class);
            getHeaders.setAccessible(true);

            Collection<String> attribs = ((Collection<String>) getHeaderNames.invoke(httpRequest, null));
            for (String headerKey : attribs) {
                String headerFullValue = StringUtils.EMPTY;
                Collection<String> headerElements = (Collection<String>) getHeaders.invoke(httpRequest, headerKey);
                for (String headerValue : headerElements) {
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


    public void insertToResponseBufferByte(byte b) {
        try {
            outputBodyBuilder.append((char) b);
//            System.out.println("inserting : " + b);
        } catch (Exception e) {
            e.printStackTrace();
            // Buffer full. discard data.
        }
    }

    public void insertToResponseBufferByte(byte[] b) {
        try {
            outputBodyBuilder.append(new String(b));
//            System.out.println("inserting : " + Arrays.asList(b));
        } catch (Exception e) {
            e.printStackTrace();
            // Buffer full. discard data.
        }
    }

    public void insertToResponseBufferByte(byte[] b, int offset, int limit) {
        try {
            outputBodyBuilder.append(new String(b, offset, limit));
//            System.out.println("inserting : " + Arrays.asList(b));
        } catch (Exception e) {
            e.printStackTrace();
            // Buffer full. discard data.
        }
    }

    public void insertToResponseBufferString(int b) {
        try {
            outputBodyBuilder.append((char) b);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void insertToResponseBufferString(char[] b, int offset, int limit) {
        try {
            outputBodyBuilder.append(new String(b, offset, limit));
            //            System.out.println("inserting : " + Arrays.asList(b));
        } catch (Exception e) {
            e.printStackTrace();
            // Buffer full. discard data.
        }
    }

    public void insertToResponseBufferString(String b, int offset, int limit) {
        try {
            outputBodyBuilder.append(StringUtils.substring(b, offset, limit));
            //            System.out.println("inserting : " + Arrays.asList(b));
        } catch (Exception e) {
            e.printStackTrace();
            // Buffer full. discard data.
        }
    }


    public void insertToResponseBuffer(Object b) {
        try {
            outputBodyBuilder.append(b);
//            System.out.println("inserting : " + Arrays.asList(b));
        } catch (Exception e) {
            e.printStackTrace();
            // Buffer full. discard data.
        }
    }

    public void insertToResponseBufferWithLF(Object b) {
        try {
            outputBodyBuilder.append(b);
            outputBodyBuilder.append(StringUtils.LF);
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

    public void updateResponseBody() {
        try {
            if (outputBodyBuilder.length() > ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().getResponseBody().length()) {
                ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().setResponseBody(outputBodyBuilder.toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void cleanState() {
        if (K2Instrumentator.enableHTTPRequestPrinting) {
            //TODO add HTTP request printing
            logger.log(LogLevel.INFO, IAgentConstants.INTERCEPTED_HTTP_REQUEST, AgentNew.class.getName());
        }
        httpRequest = null;
        isHttpRequestParsed = false;
        httpResponse = null;
        isHttpResponseParsed = false;
        printWriter = null;
        bufferOffset = 0;
        byteBuffer = ByteBuffer.allocate(1024 * 8);
        outputBodyBuilder = new StringBuilder();
    }

    public boolean isEmpty() {
        return httpRequest == null || httpResponse == null;
    }
}
