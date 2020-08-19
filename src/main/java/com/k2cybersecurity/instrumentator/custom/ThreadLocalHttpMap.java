package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
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
	public static final String NO_HTTP_REQUEST_FOUND_FOR_CURRENT_CONTEXT = "No HTTP request found for current context";
    public static final String HTTP_REQUEST_ALREADY_PARSED_FOR_CURRENT_CONTEXT = "HTTP request already parsed for current context";
    public static final String GET_METHOD = "getMethod";
    public static final String GET_REMOTE_ADDR = "getRemoteAddr";
    public static final String GET_REQUEST_URI = "getRequestURI";
    public static final String GET_QUERY_STRING = "getQueryString";
    public static final String GET_CONTENT_TYPE1 = "getContentType";
    public static final String GET_CONTENT_TYPE = GET_CONTENT_TYPE1;
    public static final String QUESTION_MARK = "?";
    public static final String GET_SERVLET_CONTEXT = "getServletContext";
    public static final String GET_CONTEXT_PATH = "getContextPath";
    public static final String GET_LOCAL_PORT = "getLocalPort";
    public static final String GET_PARAMETER_MAP = "getParameterMap";
    public static final String GET_SERVLET_PATH = "getServletPath";
    public static final String GET_PATH_TRANSLATED = "getPathTranslated";
    public static final String GET_URI_INFO = "getUriInfo";
    public static final String GET_PATH_PARAMETERS = "getPathParameters";
    public static final String ERROR = "Error : ";
    public static final String STRING_COLON = " : ";
    public static final String RAW_INTERCEPTED_REQUEST = "RAW Intercepted Request : ";
    public static final String GET_HEADER_NAMES = "getHeaderNames";
    public static final String GET_HEADERS = "getHeaders";
    public static final String STRING_SEMICOLON = "; ";
    public static final String NO_HTTP_RESPONSE_FOUND_FOR_CURRENT_CONTEXT = "No HTTP response found for current context";
    public static final String HTTP_RESPONSE_ALREADY_PARSED_FOR_CURRENT_CONTEXT = "HTTP response already parsed for current context";
    public static final String GET_CHARACTER_ENCODING = "getCharacterEncoding";
    public static final String FORWARD_SLASH = "/";
    public static final String GET_REMOTE_PORT = "getRemotePort";
    public static final String X_FORWARDED_FOR = "X-Forwarded-For";
    public static final String GET_SCHEME = "getScheme";

    private Object httpRequest;

    private boolean isHttpRequestParsed = false;

    private Object httpResponse;

    private ByteBuffer byteBuffer;

    private StringBuilder outputBodyBuilder;

	private int bufferOffset = 0;

	private int bufferLimit = 0;

	private int responseBufferLimit = 0;

	private boolean isHttpResponseParsed = false;

	private Object requestInputStream;

	private Object requestReader;

	private Object responseOutputStream;

	private Object responseWriter;

	private boolean isServiceMethodEncountered = false;


	private static ThreadLocal<ThreadLocalHttpMap> instance = new ThreadLocal<ThreadLocalHttpMap>() {
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

	public Object getRequestInputStream() {
		return requestInputStream;
	}

	public void setRequestInputStream(Object requestInputStream) {
		this.requestInputStream = requestInputStream;
	}

	public Object getRequestReader() {
		return requestReader;
	}

	public void setRequestReader(Object requestReader) {
		this.requestReader = requestReader;
	}

	public Object getResponseOutputStream() {
		return responseOutputStream;
	}

	public void setResponseOutputStream(Object responseOutputStream) {
		this.responseOutputStream = responseOutputStream;
	}

	public Object getResponseWriter() {
		return responseWriter;
	}

	public void setResponseWriter(Object responseWriter) {
		this.responseWriter = responseWriter;
	}

	public int getBufferLimit() {
		return bufferLimit;
	}

	public void setBufferLimit(int bufferLimit) {
		this.bufferLimit = bufferLimit;
	}

	public int getResponseBufferLimit() {
		return responseBufferLimit;
	}

	public void setResponseBufferLimit(int responseBufferLimit) {
		this.responseBufferLimit = responseBufferLimit;
	}

	public boolean isServiceMethodEncountered() {
		return isServiceMethodEncountered;
	}

	public void setServiceMethodEncountered(boolean serviceMethodEncountered) {
		isServiceMethodEncountered = serviceMethodEncountered;
	}

	public boolean parseHttpRequest() {
		if (httpRequest == null) {
//			logger.log(LogLevel.DEBUG, NO_HTTP_REQUEST_FOUND_FOR_CURRENT_CONTEXT, ThreadLocalHttpMap.class.getName());
			return false;
		}
		// System.out.println("Parsing HTTP request : " + httpRequest.hashCode());

		HttpRequestBean httpRequestBean = ThreadLocalExecutionMap.getInstance().getHttpRequestBean();
		AgentMetaData metaData = ThreadLocalExecutionMap.getInstance().getMetaData();

		Class requestClass = httpRequest.getClass();

		updateBody();
		try {
            Method getLocalPort = requestClass.getMethod(GET_LOCAL_PORT);
            getLocalPort.setAccessible(true);
            int serverPort = (Integer) getLocalPort.invoke(httpRequest, null);
            httpRequestBean.setServerPort(serverPort);

            Method getServletContext = requestClass.getMethod(GET_SERVLET_CONTEXT);
            getServletContext.setAccessible(true);
            Object servletContext = getServletContext.invoke(httpRequest, null);

            httpRequestBean.setServletContextObject(servletContext);

			Method getContextPath = servletContext.getClass().getMethod(GET_CONTEXT_PATH);
			getContextPath.setAccessible(true);
			String contextPath = (String) getContextPath.invoke(servletContext, null);
			if (StringUtils.isBlank(contextPath)) {
				contextPath = FORWARD_SLASH;
			}
			httpRequestBean.setContextPath(contextPath);
		} catch (Throwable e) {
            logger.log(LogLevel.DEBUG, ERROR, e, ThreadLocalHttpMap.class.getName());
        }

		if (isHttpRequestParsed) {
			// logger.log(LogLevel.DEBUG, HTTP_REQUEST_ALREADY_PARSED_FOR_CURRENT_CONTEXT,
			// ThreadLocalHttpMap.class.getName());
			return true;
		}

		try {

            Method getMethod = requestClass.getMethod(GET_METHOD);
            getMethod.setAccessible(true);
            httpRequestBean.setMethod((String) getMethod.invoke(httpRequest, null));

            Method getRemoteAddr = requestClass.getMethod(GET_REMOTE_ADDR);
            getRemoteAddr.setAccessible(true);
            httpRequestBean.setClientIP((String) getRemoteAddr.invoke(httpRequest, null));
            metaData.getIps().add(httpRequestBean.getClientIP());
            if (StringUtils.isNotBlank(httpRequestBean.getClientIP())) {
                Method getRemotePort = requestClass.getMethod(GET_REMOTE_PORT);
                getRemotePort.setAccessible(true);
                httpRequestBean.setClientPort(String.valueOf(getRemotePort.invoke(httpRequest, null)));
            }
            Map<String, String> headers = new HashMap<>();
            processHeaders(headers, httpRequest);
            httpRequestBean.setHeaders(new JSONObject(headers));

            Method getScheme = requestClass.getMethod(GET_SCHEME);
            getScheme.setAccessible(true);
            httpRequestBean.setProtocol((String) getScheme.invoke(httpRequest, null));

            Method getRequestURI = requestClass.getMethod(GET_REQUEST_URI);
            getRequestURI.setAccessible(true);
            httpRequestBean.setUrl((String) getRequestURI.invoke(httpRequest, null));

            Method getQueryString = requestClass.getMethod(GET_QUERY_STRING);
            getQueryString.setAccessible(true);
            String queryString = (String) getQueryString.invoke(httpRequest, null);

            Method getContentType = requestClass.getMethod(GET_CONTENT_TYPE);
			getContentType.setAccessible(true);
			httpRequestBean.setContentType((String) getContentType.invoke(httpRequest, null));

			if (StringUtils.isNotBlank(queryString)) {
				httpRequestBean.setUrl(httpRequestBean.getUrl() + QUESTION_MARK + queryString);
			}

			Method getParameterMap = requestClass.getMethod(GET_PARAMETER_MAP);
			getParameterMap.setAccessible(true);
			httpRequestBean.setParameterMap((Map<String, String[]>) getParameterMap.invoke(httpRequest, null));

			Method getPathTranslated = requestClass.getMethod(GET_PATH_TRANSLATED);
			getPathTranslated.setAccessible(true);
			httpRequestBean.setPathParams((String) getPathTranslated.invoke(httpRequest, null));
			try {
				Method getUriInfo = requestClass.getMethod(GET_URI_INFO);
				getUriInfo.setAccessible(true);
				Object uriInfo = getUriInfo.invoke(httpRequest, null);

				if (uriInfo != null) {
					Method getPathParameters = uriInfo.getClass().getMethod(GET_PATH_PARAMETERS);
					getPathParameters.setAccessible(true);
					httpRequestBean
							.setPathParameterMap(new HashMap<>((Map<String, String>) getParameterMap.invoke(uriInfo)));
				}
			} catch (NoSuchMethodException ex) {
			}



			isHttpRequestParsed = true;
			return true;
		} catch (Throwable e) {
            logger.log(LogLevel.DEBUG, ERROR, e, ThreadLocalHttpMap.class.getName());
//			e.printStackTrace();
        } finally {
//			logger.log(LogLevel.DEBUG,
//					RAW_INTERCEPTED_REQUEST + ThreadLocalExecutionMap.getInstance().getHttpRequestBean(),
//					ThreadLocalHttpMap.class.getName());
		}
		return !httpRequestBean.isEmpty();
	}

	public void processHeaders(Map<String, String> headers, Object httpRequest) {
		try {
			Class requestClass = httpRequest.getClass();

			Method getHeaderNames = requestClass.getMethod(GET_HEADER_NAMES, null);
			getHeaderNames.setAccessible(true);
			Method getHeaders = requestClass.getMethod(GET_HEADERS, String.class);
			getHeaders.setAccessible(true);

			Enumeration<String> attribs = ((Enumeration<String>) getHeaderNames.invoke(httpRequest, null));
			while (attribs.hasMoreElements()) {
                boolean takeNextValue = false;
                String headerKey = attribs.nextElement();
                if (AgentUtils.getInstance().getAgentPolicy() != null
                        && AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getIpBlocking().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getIpBlocking().getIpDetectViaXFF()
                        && StringUtils.equalsAnyIgnoreCase(headerKey, X_FORWARDED_FOR)) {
                    takeNextValue = true;
                } else if (StringUtils.equalsAnyIgnoreCase(headerKey, IAgentConstants.K2_FUZZ_REQUEST_ID)) {
                    ThreadLocalExecutionMap.getInstance().getMetaData().setK2FuzzRequest(true);
                }
                String headerFullValue = StringUtils.EMPTY;
                Enumeration<String> headerElements = (Enumeration<String>) getHeaders.invoke(httpRequest, headerKey);
                while (headerElements.hasMoreElements()) {
                    String headerValue = headerElements.nextElement();
                    if (!headerValue.isEmpty()) {
//						headerFullValue = headerValue;
//					} else {
                        if (takeNextValue) {
                            ThreadLocalExecutionMap.getInstance().getMetaData().setClientDetectedFromXFF(true);
                            ThreadLocalExecutionMap.getInstance().getHttpRequestBean().setClientIP(headerValue);
                            ThreadLocalExecutionMap.getInstance().getMetaData().getIps()
                                    .add(ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getClientIP());
                            ThreadLocalExecutionMap.getInstance().getHttpRequestBean().setClientPort(StringUtils.EMPTY);
                            takeNextValue = false;
                        }
                        if (StringUtils.isBlank(headerFullValue)) {
                            headerFullValue = headerValue;
                        } else {
                            headerFullValue = StringUtils.joinWith(STRING_SEMICOLON, headerFullValue, headerValue);
                        }
                    }
				}
				headers.put(headerKey, headerFullValue);
			}
		} catch (Throwable e) {
            logger.log(LogLevel.DEBUG, ERROR, e, ThreadLocalHttpMap.class.getName());
        }
	}

	public boolean parseHttpResponse() {

		// TODO : To be implemented
		if (httpResponse == null) {
//			logger.log(LogLevel.DEBUG, NO_HTTP_RESPONSE_FOUND_FOR_CURRENT_CONTEXT, ThreadLocalHttpMap.class.getName());
			return false;
		}
		// System.out.println("Parsing HTTP response : " + httpResponse.hashCode());
		HttpRequestBean httpRequestBean = ThreadLocalExecutionMap.getInstance().getHttpRequestBean();

		try {
			updateResponseBody();

			if (isHttpResponseParsed) {
//				logger.log(LogLevel.DEBUG, HTTP_RESPONSE_ALREADY_PARSED_FOR_CURRENT_CONTEXT,
//						ThreadLocalHttpMap.class.getName());
				return true;
			}

			Class responseClass = httpResponse.getClass();

			Method getCharacterEncoding = responseClass.getMethod(GET_CHARACTER_ENCODING);
			getCharacterEncoding.setAccessible(true);
			httpRequestBean.getHttpResponseBean()
					.setResponseCharacterEncoding((String) getCharacterEncoding.invoke(httpResponse, null));

			Method getContentType = responseClass.getMethod(GET_CONTENT_TYPE1);
			getContentType.setAccessible(true);
			httpRequestBean.getHttpResponseBean()
					.setResponseContentType((String) getContentType.invoke(httpResponse, null));

			Map<String, String> headers = new HashMap<>();
			processResponseHeaders(headers, httpResponse);
			httpRequestBean.getHttpResponseBean().setHeaders(new JSONObject(headers));

			// TODO: based on content info, parse/decode the received reponse data here.
			// System.out.println("Parsing HTTP response completed : " +
			// httpResponse.hashCode() + " :: " + httpRequestBean.getHttpResponseBean());

			isHttpResponseParsed = true;
			return true;

		} catch (Throwable e) {
            logger.log(LogLevel.DEBUG, ERROR, e, ThreadLocalHttpMap.class.getName());
        }
		return !httpRequestBean.getHttpResponseBean().isEmpty();
	}

	public void processResponseHeaders(Map<String, String> headers, Object httpRequest) {
		try {
			Class requestClass = httpRequest.getClass();

			Method getHeaderNames = requestClass.getMethod(GET_HEADER_NAMES, null);
			getHeaderNames.setAccessible(true);
			Method getHeaders = requestClass.getMethod(GET_HEADERS, String.class);
			getHeaders.setAccessible(true);

			Collection<String> attribs = ((Collection<String>) getHeaderNames.invoke(httpRequest, null));
			for (String headerKey : attribs) {
				String headerFullValue = StringUtils.EMPTY;
				Collection<String> headerElements = (Collection<String>) getHeaders.invoke(httpRequest, headerKey);
				for (String headerValue : headerElements) {
					if (headerFullValue.isEmpty()) {
						headerFullValue = headerValue;
					} else {
						headerFullValue += STRING_SEMICOLON + headerValue;
					}
				}
				headers.put(headerKey, headerFullValue);
			}
		} catch (Throwable e) {
            logger.log(LogLevel.DEBUG, ERROR, e, ThreadLocalHttpMap.class.getName());
        }
	}

	public void insertToRequestByteBuffer(byte b) {
		if (ThreadLocalExecutionMap.getInstance().getHttpRequestBean().isDataTruncated())
			return;
		try {
			byteBuffer.put(b);
			// System.out.println("inserting : " + b);
		} catch (Throwable e) {
			ThreadLocalExecutionMap.getInstance().getHttpRequestBean().setDataTruncated(true);
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void insertToRequestByteBuffer(byte[] b) {
		if (ThreadLocalExecutionMap.getInstance().getHttpRequestBean().isDataTruncated())
			return;
		try {
			byteBuffer.put(b);
			// System.out.println("inserting : " + Arrays.asList(b));
		} catch (Throwable e) {
			ThreadLocalExecutionMap.getInstance().getHttpRequestBean().setDataTruncated(true);
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void insertToRequestByteBuffer(byte[] b, int offset, int limit) {
		if (ThreadLocalExecutionMap.getInstance().getHttpRequestBean().isDataTruncated())
			return;
		try {
			byteBuffer.put(b, offset, limit);
			// System.out.println("inserting : " + Arrays.asList(b));
		} catch (Throwable e) {
			ThreadLocalExecutionMap.getInstance().getHttpRequestBean().setDataTruncated(true);
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void insertToResponseBufferInt(int b) {
		try {
			outputBodyBuilder.append((char) b);
			// System.out.println("inserting : " + b);
		} catch (Throwable e) {
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void insertToResponseBufferByte(byte[] b) {
		try {
			outputBodyBuilder.append(new String(b));
			// System.out.println("inserting : " + Arrays.asList(b));
		} catch (Throwable e) {
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void insertToResponseBufferByte(byte[] b, int offset, int limit) {
		try {
			outputBodyBuilder.append(new String(b, offset, limit));
			// System.out.println("inserting : " + Arrays.asList(b));
		} catch (Throwable e) {
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void insertToResponseBufferString(int b) {
		try {
			outputBodyBuilder.append((char) b);
		} catch (Throwable e) {
			// e.printStackTrace();
		}
	}

	public void insertToResponseBufferString(char[] b, int offset, int limit) {
		try {
			outputBodyBuilder.append(new String(b, offset, limit).trim());
			// System.out.println("inserting : " + Arrays.asList(b));
		} catch (Throwable e) {
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void insertToResponseBufferString(String b, int offset, int limit) {
		try {
			outputBodyBuilder.append(StringUtils.substring(b, offset, limit));
			// System.out.println("inserting : " + Arrays.asList(b));
		} catch (Throwable e) {
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void insertToResponseBuffer(Object b) {
		try {
			outputBodyBuilder.append(b);
			// System.out.println("inserting : " + Arrays.asList(b));
		} catch (Throwable e) {
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void insertToResponseBufferWithLF(Object b) {
		try {
			outputBodyBuilder.append(b);
			outputBodyBuilder.append(StringUtils.LF);
			// System.out.println("inserting : " + Arrays.asList(b));
		} catch (Throwable e) {
			// e.printStackTrace();
			// Buffer full. discard data.
		}
	}

	public void updateBody() {
		try {
			if (byteBuffer.position() > bufferOffset) {
				String oldBody = ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getBody();
				ThreadLocalExecutionMap.getInstance().getHttpRequestBean()
						.setBody(oldBody + new String(byteBuffer.array(), bufferOffset, byteBuffer.position()).trim());
				bufferOffset = byteBuffer.position();
			}
		} catch (Throwable e) {
			// e.printStackTrace();
		}
	}

	public void updateResponseBody() {
		try {
			if (outputBodyBuilder.length() > ThreadLocalExecutionMap.getInstance().getHttpRequestBean()
					.getHttpResponseBean().getResponseBody().length()) {
				ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean()
						.setResponseBody(outputBodyBuilder.toString().trim());
			}
		} catch (Throwable e) {
			// e.printStackTrace();
		}
	}

	public void cleanState() {

		httpRequest = null;
		isHttpRequestParsed = false;
		httpResponse = null;
		isHttpResponseParsed = false;
		bufferOffset = 0;
		bufferLimit = 0;
		responseBufferLimit = 0;
		byteBuffer = ByteBuffer.allocate(1024 * 8);
		outputBodyBuilder = new StringBuilder();
		requestInputStream = null;
		requestReader = null;
		responseOutputStream = null;
		responseWriter = null;
		isServiceMethodEncountered = false;
		ThreadLocalHTTPIOLock.getInstance().resetLock();
	}

	public void printInterceptedRequestResponse() {
		if (K2Instrumentator.enableHTTPRequestPrinting) {
			logger.log(LogLevel.INFO,
					String.format(IAgentConstants.INTERCEPTED_HTTP_REQUEST,
							ThreadLocalExecutionMap.getInstance().getHttpRequestBean(),
							ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean()),
					ThreadLocalHttpMap.class.getName());
		}
	}

	/**
	 * As we have removed httpResponse from this check, this might fuck things up at
	 * places we yet not know. If any unwarrented error occurs
	 */
	public boolean isEmpty() {
		return httpRequest == null;
	}
}
