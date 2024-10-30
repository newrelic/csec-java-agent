package com.nr.agent.security.instrumentation.spring.webmvc;

import com.newrelic.api.agent.security.schema.StringUtils;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

public class DummyRequest implements HttpServletRequest {
    protected String queryString = StringUtils.EMPTY;
    protected String pathInfo;
    protected String servletPath = StringUtils.SEPARATOR;
    private String method;
    private static Enumeration<String> dummyEnum = new Enumeration<String>() {
        public boolean hasMoreElements() {
            return false;
        }

        public String nextElement() {
            return null;
        }
    };

    public DummyRequest(String pathInfo, String method) {
        this.pathInfo = pathInfo;
        this.method = method;
    }

    public String getContextPath() {
        return null;
    }

    public ServletRequest getRequest() {
        return this;
    }

    public String getQueryString() {
        return this.queryString;
    }

    public String getPathInfo() {
        return this.pathInfo;
    }

    public String getServletPath() {
        return this.servletPath;
    }

    public String getMethod() {
        return this.method;
    }

    public Object getAttribute(String name) {
        return pathInfo;
    }

    public Enumeration<String> getAttributeNames() {
        return null;
    }

    public String getCharacterEncoding() {
        return null;
    }

    public int getContentLength() {
        return -1;
    }

    public long getContentLengthLong() {
        return -1L;
    }

    public String getContentType() {
        return null;
    }

    public ServletInputStream getInputStream() throws IOException {
        return null;
    }

    public Locale getLocale() {
        return null;
    }

    public Enumeration<Locale> getLocales() {
        return null;
    }

    public String getProtocol() {
        return null;
    }

    public BufferedReader getReader() throws IOException {
        return null;
    }

    public String getRealPath(String path) {
        return null;
    }

    public String getRemoteAddr() {
        return null;
    }

    public String getRemoteHost() {
        return null;
    }

    public String getScheme() {
        return null;
    }

    public String getServerName() {
        return null;
    }

    public int getServerPort() {
        return -1;
    }

    public boolean isSecure() {
        return false;
    }

    public void removeAttribute(String name) {
    }

    public void setAttribute(String name, Object value) {
    }

    public void setCharacterEncoding(String enc) throws UnsupportedEncodingException {
    }

    public String getParameter(String name) {
        return null;
    }

    public Map<String, String[]> getParameterMap() {
        return null;
    }

    public Enumeration<String> getParameterNames() {
        return dummyEnum;
    }

    public String[] getParameterValues(String name) {
        return null;
    }

    public RequestDispatcher getRequestDispatcher(String path) {
        return null;
    }

    public String getAuthType() {
        return null;
    }

    public Cookie[] getCookies() {
        return null;
    }

    public long getDateHeader(String name) {
        return -1L;
    }

    public String getHeader(String name) {
        return null;
    }

    public Enumeration<String> getHeaders(String name) {
        return null;
    }

    public Enumeration<String> getHeaderNames() {
        return null;
    }

    public int getIntHeader(String name) {
        return -1;
    }

    public String getPathTranslated() {
        return null;
    }

    public String getRemoteUser() {
        return null;
    }

    public String getRequestedSessionId() {
        return null;
    }

    public String getRequestURI() {
        return null;
    }

    public StringBuffer getRequestURL() {
        return null;
    }

    public HttpSession getSession() {
        return null;
    }

    public HttpSession getSession(boolean create) {
        return null;
    }

    public String changeSessionId() {
        return null;
    }

    public boolean isRequestedSessionIdFromCookie() {
        return false;
    }

    public boolean isRequestedSessionIdFromURL() {
        return false;
    }

    public boolean isRequestedSessionIdFromUrl() {
        return false;
    }

    public boolean isRequestedSessionIdValid() {
        return false;
    }

    public void setRequestedSessionCookiePath(String cookiePath) {
    }

    public boolean isUserInRole(String role) {
        return false;
    }

    public Principal getUserPrincipal() {
        return null;
    }

    public String getLocalAddr() {
        return null;
    }

    public String getLocalName() {
        return null;
    }

    public int getLocalPort() {
        return -1;
    }

    public int getRemotePort() {
        return -1;
    }

    public DispatcherType getDispatcherType() {
        return null;
    }

    public AsyncContext startAsync() throws IllegalStateException {
        return null;
    }

    public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException {
        return null;
    }

    public boolean isAsyncStarted() {
        return false;
    }

    public boolean isAsyncSupported() {
        return false;
    }

    public AsyncContext getAsyncContext() {
        return null;
    }

    public Collection<Part> getParts() {
        return null;
    }

    public Part getPart(String name) {
        return null;
    }

    public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
        return false;
    }

    public void login(String username, String password) throws ServletException {
    }

    public void logout() throws ServletException {

    }

    public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) {
        return null;
    }

    public ServletContext getServletContext() {
        return null;
    }

}

