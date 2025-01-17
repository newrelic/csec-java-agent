package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.http.ReadResult;
import com.newrelic.api.agent.security.schema.http.RequestLayout;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.Header;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;

import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

import static com.newrelic.api.agent.security.instrumentation.helpers.ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST;


public class ApacheHttpClientWrapper {
    public static final String SEPARATOR_QUESTION_MARK = "?";
    public static final String SUFFIX_SLASH = "/";
    private final ApacheProxyManager proxyManager;
    private final PoolingHttpClientConnectionManager connectionManager;
    private final CloseableHttpClient httpClient;
    public static final String APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";

    public static final String GZIP_ENCODING = "gzip";

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    /**
     * NR data posting client
     * */
    public ApacheHttpClientWrapper(ApacheProxyManager proxyManager, SSLContext sslContext, int defaultTimeoutInMillis) {
        this.proxyManager = proxyManager;
        this.connectionManager = createHttpClientConnectionManager(sslContext);
        this.httpClient = createHttpClient(defaultTimeoutInMillis);
    }

    /**
     * IAST request repeater client
     * */
    public ApacheHttpClientWrapper(int requestTimeoutInMillis) {
        this.proxyManager = null;
        SSLContext sslContext = null;
        try {
            final TrustStrategy acceptingTrustStrategy = (cert, authType) -> true;
            sslContext = SSLContexts.custom()
                    .loadTrustMaterial(null, acceptingTrustStrategy)
                    .build();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException exception){

        }
        this.connectionManager = createHttpClientConnectionManager(sslContext);
        this.httpClient = HttpClientBuilder.create()
                .disableDefaultUserAgent()
                .disableContentCompression()
                .disableCookieManagement()
                .disableAuthCaching()
                .disableConnectionState()
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .setDefaultRequestConfig(RequestConfig.custom()
                        // Timeout in millis until a connection is established.
                        .setConnectTimeout(requestTimeoutInMillis)
                        // Timeout in millis when requesting a connection from the connection manager.
                        // This timeout should be longer than the connect timeout to avoid potential ConnectionPoolTimeoutExceptions.
                        .setConnectionRequestTimeout(requestTimeoutInMillis * 2)
                        // Timeout in millis for non-blocking socket I/O operations (aka max inactivity between two consecutive data packets).
                        .setSocketTimeout(requestTimeoutInMillis)
                        .build())
                .setDefaultSocketConfig(SocketConfig.custom()
                        // Timeout in millis for non-blocking socket I/O operations.
                        .setSoTimeout(requestTimeoutInMillis)
                        .setSoKeepAlive(true)
                        .build())
                .addInterceptorFirst(new ReplayRequestLoggingInterceptor())
                .addInterceptorLast(new ReplayResponseLoggingInterceptor())
                .setConnectionManager(connectionManager).build();
    }

    private static final String USER_AGENT_HEADER_VALUE = initUserHeaderValue();

    private static String initUserHeaderValue() {
        String arch = "unknown";
        String javaVersion = "unknown";
        try {
            arch = System.getProperty("os.arch");
            javaVersion = System.getProperty("java.version");
        } catch (Exception ignored) {
        }
        return MessageFormat.format("NewRelic-SecurityJavaAgent/{0} ({1}) (java {1} {2})", AgentInfo.getInstance().getBuildInfo().getCollectorVersion(), AgentInfo.getInstance().getBuildInfo().getBuildNumber(), javaVersion, arch);
    }

    private static PoolingHttpClientConnectionManager createHttpClientConnectionManager(SSLContext sslContext) {
        // Using the pooling manager here for thread safety.
        PoolingHttpClientConnectionManager httpClientConnectionManager = new PoolingHttpClientConnectionManager(
                RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("http", PlainConnectionSocketFactory.getSocketFactory())
                        .register("https", sslContext != null ?
                                new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE) : SSLConnectionSocketFactory.getSocketFactory())
                        .build());

        // We only allow one connection at a time to the backend.
        // Anymore and the agent hangs during the initial request to the connect endpoint.
        httpClientConnectionManager.setMaxTotal(1);
        httpClientConnectionManager.setDefaultMaxPerRoute(1);

        return httpClientConnectionManager;
    }

    private CloseableHttpClient createHttpClient(int requestTimeoutInMillis) {
        HttpClientBuilder builder = HttpClientBuilder.create()
                .setUserAgent(USER_AGENT_HEADER_VALUE)
                .setDefaultHeaders(Arrays.<Header>asList(
                        new BasicHeader("Connection", "Keep-Alive"),
                        new BasicHeader("CONTENT-TYPE", "application/json")))
                .setSSLHostnameVerifier(new DefaultHostnameVerifier())
                .setDefaultRequestConfig(RequestConfig.custom()
                        // Timeout in millis until a connection is established.
                        .setConnectTimeout(requestTimeoutInMillis)
                        // Timeout in millis when requesting a connection from the connection manager.
                        // This timeout should be longer than the connect timeout to avoid potential ConnectionPoolTimeoutExceptions.
                        .setConnectionRequestTimeout(requestTimeoutInMillis * 2)
                        // Timeout in millis for non-blocking socket I/O operations (aka max inactivity between two consecutive data packets).
                        .setSocketTimeout(requestTimeoutInMillis)
                        .build())
                .setDefaultSocketConfig(SocketConfig.custom()
                        // Timeout in millis for non-blocking socket I/O operations.
                        .setSoTimeout(requestTimeoutInMillis)
                        .setSoKeepAlive(true)
                        .build())
                .setConnectionManager(connectionManager);

        if (proxyManager.getProxy() != null) {
            builder.setProxy(proxyManager.getProxy());
        }

        return builder.build();
    }

    public void shutdown() {
        connectionManager.closeIdleConnections(0, TimeUnit.SECONDS);
    }

    private HttpContext createContext() {
        return proxyManager.updateContext(HttpClientContext.create());
    }

    public ReadResult execute(RequestLayout requestLayout, List<String> pathParams, Map<String, String> queryParams,
                                         Map<String, String> headers, byte[] body) throws IOException, URISyntaxException {
        HttpUriRequest request;
        try {
            request = buildHttpRequest(requestLayout, pathParams, queryParams, headers, body);
        } catch (ApacheHttpExceptionWrapper e) {
            logger.log(LogLevel.WARNING, "Error while building request for API: " + requestLayout.getApi() + "with content requestLayout : " + requestLayout +" pathParams: "+ pathParams+" queryParams: "+ queryParams+" headers: "+ headers+" body: "+ Arrays.toString(body), ApacheHttpClientWrapper.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.WARNING, "Error while building request for API: " + requestLayout.getApi() + "with content requestLayout : " + requestLayout +" pathParams: "+ pathParams+" queryParams: "+ queryParams+" headers: "+ headers+" body: "+ Arrays.toString(body), e, ApacheHttpClientWrapper.class.getName());
            return null;
        }
        logger.log(LogLevel.FINEST, "Executing request: " + request, ApacheHttpClientWrapper.class.getName());

        try (CloseableHttpResponse response = httpClient.execute(request, createContext())) {
            return mapResponseToResult(response);
        } catch (HttpHostConnectException hostConnectException) {
            String message = "HttpHostConnectException Error while executing request %s message : %s";
            logger.log(LogLevel.FINE, String.format(message, request, hostConnectException.getMessage()), ApacheHttpClientWrapper.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.WARNING, String.format(message, request, hostConnectException.getMessage()), hostConnectException, ApacheHttpClientWrapper.class.getName());
            throw hostConnectException;
        } catch (ApacheHttpExceptionWrapper e) {
            logger.log(LogLevel.WARNING, "Error while reading response for request: " + request, ApacheHttpClientWrapper.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.WARNING, "Error while reading response for request: " + request, e, ApacheHttpClientWrapper.class.getName());
            return null;
        }
    }

    public ReadResult execute(HttpRequest httpRequest, String endpoint, String fuzzRequestId) throws IOException, URISyntaxException, ApacheHttpExceptionWrapper {
        return execute(httpRequest, endpoint, fuzzRequestId, false);
    }


    public ReadResult execute(HttpRequest httpRequest, String endpoint, String fuzzRequestId, boolean addEventIgnoreHeader) throws IOException, URISyntaxException, ApacheHttpExceptionWrapper {
        HttpUriRequest request = buildIastFuzzRequest(httpRequest, endpoint, addEventIgnoreHeader);
        logger.log(LogLevel.FINEST, String.format("Executing request %s: %s", fuzzRequestId, request), ApacheHttpClientWrapper.class.getName());

        try (CloseableHttpResponse response = httpClient.execute(request)) {
            return mapResponseToResult(response);
        } catch (IOException hostConnectException) {
            String message = "IOException Error while executing request %s: %s message : %s";
            logger.log(LogLevel.FINE, String.format(message, fuzzRequestId, request, hostConnectException.getMessage()), ApacheHttpClientWrapper.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.WARNING, String.format(message, fuzzRequestId, request, hostConnectException.getMessage()), hostConnectException, ApacheHttpClientWrapper.class.getName());
            throw hostConnectException;
        }
    }

    private HttpUriRequest buildIastFuzzRequest(HttpRequest httpRequest, String endpoint, boolean addEventIgnoreHeader) throws URISyntaxException, UnsupportedEncodingException, ApacheHttpExceptionWrapper {
        RequestBuilder requestBuilder = getRequestBuilder(httpRequest.getMethod());
        String requestUrl = httpRequest.getUrl();
        if (StringUtils.isBlank(requestUrl)) {
            throw new ApacheHttpExceptionWrapper("Request URL is empty");
        }
        requestBuilder.setUri(createURL(endpoint, requestUrl));
        if(StringUtils.startsWith(httpRequest.getContentType(), APPLICATION_X_WWW_FORM_URLENCODED)){
            requestBuilder.setEntity(new UrlEncodedFormEntity(buildFormParameters(httpRequest.getParameterMap())));
        }
        setHeader(requestBuilder, httpRequest.getHeaders());
        if(addEventIgnoreHeader) {
            requestBuilder.setHeader(NR_CSEC_JAVA_HEAD_REQUEST, "true");
        }

        if (httpRequest.getBody() != null && StringUtils.isNotBlank(httpRequest.getBody())) {
            requestBuilder.setEntity(new StringEntity(httpRequest.getBody().toString()));
        }

        return requestBuilder.build();
    }

    private URI createURL(String endpoint, String requestUrl) {
        if (StringUtils.isBlank(requestUrl)) {
            return URI.create(endpoint);
        }
        if (StringUtils.endsWith(endpoint, SUFFIX_SLASH) && StringUtils.startsWith(requestUrl, SUFFIX_SLASH)) {
            return URI.create(endpoint + requestUrl.substring(1));
        } else if (StringUtils.endsWith(endpoint, SUFFIX_SLASH) || StringUtils.startsWith(requestUrl, SUFFIX_SLASH)) {
            return URI.create(endpoint + requestUrl);
        } else {
            return URI.create(endpoint + SUFFIX_SLASH + requestUrl);
        }
    }

    private List<? extends NameValuePair> buildFormParameters(Map<String, String[]> parameterMap) {
        List<NameValuePair> formParameters = new ArrayList<>();
        for (Map.Entry<String, String[]> formData : parameterMap.entrySet()) {
            for (String value : formData.getValue()) {
                formParameters.add(new BasicNameValuePair(formData.getKey(), value));
            }
        }
        return formParameters;
    }

    private HttpUriRequest buildHttpRequest(RequestLayout requestLayout, List<String> pathParams, Map<String, String> queryParams, Map<String, String> headers, byte[] body)
            throws URISyntaxException, ApacheHttpExceptionWrapper {
        RequestBuilder requestBuilder = getRequestBuilder(requestLayout.getMethod());
        String apiPath = setPathParams(requestLayout.getPath(), pathParams);
        URI uri = setQueryParams(requestLayout.getEndpoint(), apiPath, queryParams);
        requestBuilder.setUri(uri);
        setHeader(requestBuilder, headers);
        if(body != null) {
            requestBuilder.setEntity(new ByteArrayEntity(body));
        }
        return requestBuilder.build();
    }

    private static RequestBuilder getRequestBuilder(String method) throws ApacheHttpExceptionWrapper {
        RequestBuilder requestBuilder = null;
        switch (method){
            case "GET":
                requestBuilder = RequestBuilder.get();
                break;
            case "POST":
                requestBuilder = RequestBuilder.post();
                break;
            case "PUT":
                requestBuilder = RequestBuilder.put();
                break;
            case "DELETE":
                requestBuilder = RequestBuilder.delete();
                break;
            case "HEAD":
                requestBuilder = RequestBuilder.head();
                break;
            case "OPTIONS":
                requestBuilder = RequestBuilder.options();
                break;
            case "PATCH":
                requestBuilder = RequestBuilder.patch();
                break;
           case "TRACE":
               requestBuilder = RequestBuilder.trace();
               break;
            default:
                throw new ApacheHttpExceptionWrapper("Unsupported HTTP method: " + method);
        }
        return requestBuilder;
    }

    private void setHeader(RequestBuilder requestBuilder, Map<String, String> headers) throws ApacheHttpExceptionWrapper {
        if(headers == null) {
            throw new ApacheHttpExceptionWrapper("Headers are null");
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if(StringUtils.isBlank(entry.getKey()) || StringUtils.isBlank(entry.getValue()) || entry.getKey().equalsIgnoreCase("content-length")) {
                continue;
            }
            requestBuilder.setHeader(entry.getKey(), entry.getValue());
        }
    }


    private String setPathParams(String path, List<String> pathParams) {
        if(pathParams == null || pathParams.isEmpty()) {
            return path;
        }
        return String.format(path, pathParams.toArray(new String[pathParams.size()]));
    }

    private URI setQueryParams(String endpoint, String uri, Map<String, String> queryParams) throws URISyntaxException {
        URIBuilder builder = new URIBuilder(endpoint);
        builder.setPath(uri);
        if (queryParams == null) {
            return builder.build();
        }

        for (Map.Entry<String, String> param : queryParams.entrySet()) {
            builder.addParameter(param.getKey(), param.getValue());
        }
        return  builder.build();
    }

    private ReadResult mapResponseToResult(HttpResponse response) throws IOException, ApacheHttpExceptionWrapper {
        StatusLine statusLine = response.getStatusLine();
        if (statusLine == null) {
            throw new ApacheHttpExceptionWrapper("HttpClient returned null status line");
        }

        return ReadResult.create(
                statusLine.getStatusCode(),
                readResponseBody(response));
    }

    /**
     * Returns the first <a href="https://tools.ietf.org/html/rfc7235#section-4.3">Proxy-Authenticate</a> header
     * for indicating to the user that their proxy configuration isn't set up correctly.
     *
     * @param response The HttpResponse from the client
     * @return The value of the header.
     */
    private String getFirstProxyAuthenticateHeader(HttpResponse response) {
        String proxyAuthenticateValue = null;
        Header proxyAuthenticateHeader = response.getFirstHeader("Proxy-Authenticate");
        if (proxyAuthenticateHeader != null) {
            proxyAuthenticateValue = proxyAuthenticateHeader.getValue();
        }
        return proxyAuthenticateValue;
    }

    private String readResponseBody(HttpResponse response) throws IOException, ApacheHttpExceptionWrapper {
        HttpEntity entity = response.getEntity();
        if (entity == null) {
            throw new ApacheHttpExceptionWrapper("The http response entity was null");
        }
        try (
                InputStream is = entity.getContent();
                BufferedReader in = getBufferedReader(response, is)
        ) {
            StringBuilder responseBody = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                responseBody.append(line);
            }
            return responseBody.toString();
        }
    }

    private BufferedReader getBufferedReader(HttpResponse response, InputStream is) throws IOException {
        Header encodingHeader = response.getFirstHeader("content-encoding");
        if (encodingHeader != null) {
            String encoding = encodingHeader.getValue();
            if (GZIP_ENCODING.equals(encoding)) {
                is = new GZIPInputStream(is);
            }
        }
        return new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
    }
}
