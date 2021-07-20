package com.k2cybersecurity.intcodeagent.logging;


import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;

public class ServletEventProcessor implements Runnable {

    private Object firstElement;

    private Object request;
    private HttpRequestBean servletInfo;
    private String sourceString;
    private Long threadId;

    /**
     * @return the firstElement
     */
    public Object getFirstElement() {
        return firstElement;
    }

    /**
     * @param firstElement the firstElement to set
     */
    public void setFirstElement(Object firstElement) {
        this.firstElement = firstElement;
    }

    /**
     * @return the servletInfo
     */
    public HttpRequestBean getServletInfo() {
        return servletInfo;
    }

    /**
     * @param servletInfo the servletInfo to set
     */
    public void setServletInfo(HttpRequestBean servletInfo) {
        this.servletInfo = servletInfo;
    }

    /**
     * @return the sourceString
     */
    public String getSourceString() {
        return sourceString;
    }

    /**
     * @param sourceString the sourceString to set
     */
    public void setSourceString(String sourceString) {
        this.sourceString = sourceString;
    }

    /**
     * @return the threadId
     */
    public Long getThreadId() {
        return threadId;
    }

    /**
     * @param threadId the threadId to set
     */
    public void setThreadId(Long threadId) {
        this.threadId = threadId;
    }

    public ServletEventProcessor(Object firstElement, Object request, HttpRequestBean servletInfo, String sourceString,
                                 long threadId) {
        this.firstElement = firstElement;
        this.request = request;
        this.servletInfo = servletInfo;
        this.sourceString = sourceString;
        this.threadId = threadId;
    }

    @Override
    public void run() {
    }

    /**
     * @return the request
     */
    public Object getRequest() {
        return request;
    }

    /**
     * @param request the request to set
     */
    public void setRequest(Object request) {
        this.request = request;
    }

}
