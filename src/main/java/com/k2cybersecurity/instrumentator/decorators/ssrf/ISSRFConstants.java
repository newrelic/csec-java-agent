package com.k2cybersecurity.instrumentator.decorators.ssrf;

public interface ISSRFConstants {

	String APACHE_HTTP_REQUEST_EXECUTOR_METHOD = "protected org.apache.http.HttpResponse org.apache.http.protocol.HttpRequestExecutor.doSendRequest(org.apache.http.HttpRequest,org.apache.http.HttpClientConnection,org.apache.http.protocol.HttpContext) throws java.io.IOException,org.apache.http.HttpException";

	String JAVA_OPEN_CONNECTION_METHOD2 = "protected java.net.URLConnection sun.net.www.protocol.http.Handler.openConnection(java.net.URL,java.net.Proxy) throws java.io.IOException";
	String JAVA_OPEN_CONNECTION_METHOD2_HTTPS = "protected java.net.URLConnection sun.net.www.protocol.https.Handler.openConnection(java.net.URL,java.net.Proxy) throws java.io.IOException";
	String JAVA_OPEN_CONNECTION_METHOD2_HTTPS_2 = "protected java.net.URLConnection com.sun.net.ssl.internal.www.protocol.https.Handler.openConnection(java.net.URL,java.net.Proxy) throws java.io.IOException";

	String JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_METHOD = "public jdk.incubator.http.HttpResponseImpl<T> jdk.incubator.http.MultiExchange.response() throws java.io.IOException,java.lang.InterruptedException";
	String JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_ASYNC_METHOD = "public java.util.concurrent.CompletableFuture<jdk.incubator.http.HttpResponseImpl<T>> jdk.incubator.http.MultiExchange.responseAsync()";

	String APACHE_COMMONS_HTTP_METHOD_DIRECTOR_METHOD = "private void org.apache.commons.httpclient.HttpMethodDirector.executeWithRetry(org.apache.commons.httpclient.HttpMethod) throws java.io.IOException,org.apache.commons.httpclient.HttpException";

	String OKHTTP_HTTP_ENGINE_METHOD = "public void com.squareup.okhttp.internal.http.HttpEngine.sendRequest() throws com.squareup.okhttp.internal.http.RequestException,com.squareup.okhttp.internal.http.RouteException,java.io.IOException";

	String WEBLOGIC_OPEN_CONNECTION_METHOD = "protected java.net.URLConnection weblogic.net.http.Handler.openConnection(java.net.URL,java.net.Proxy) throws java.io.IOException";

	String FIELD_URI = "uri";
	String FIELD_REQUEST = "request";
	String JDK_INCUBATOR_HTTP_MULTI_EXCHANGE = "jdk.incubator.http.MultiExchange";

	String GET_PATH = "getPath";
	String GET_HOST = "getHost";
	String GET_URI = "getURI";
	String EMPTY = "";
	String HTTP_TARGET_HOST = "http.target_host";
	String GET_ATTRIBUTE = "getAttribute";
	String REGEX_SPACE = "\\s+";
	String GET_REQUEST_LINE = "getRequestLine";
	String ORG_APACHE_HTTP_PROTOCOL_HTTP_CONTEXT = "org.apache.http.protocol.HttpContext";
	String ORG_APACHE_HTTP_HTTP_REQUEST = "org.apache.http.HttpRequest";
	String ORG_APACHE_COMMONS_HTTPCLIENT_URI = "org.apache.commons.httpclient.URI";
	String ORG_APACHE_COMMONS_HTTPCLIENT_HTTP_METHOD = "org.apache.commons.httpclient.HttpMethod";
	String FIELD_URL = "url";
	String METHOD_GET_REQUEST = "getRequest";

}
