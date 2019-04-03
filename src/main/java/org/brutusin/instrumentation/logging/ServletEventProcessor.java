package org.brutusin.instrumentation.logging;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

public class ServletEventProcessor implements Runnable {

	private Object firstElement;
	private Object request;
	private ServletInfo servletInfo;
	private String sourceString;
	private Long threadId;

	/**
	 * @return the firstElement
	 */
	public Object getFirstElement() {
		return firstElement;
	}

	/**
	 * @param firstElement
	 *            the firstElement to set
	 */
	public void setFirstElement(Object firstElement) {
		this.firstElement = firstElement;
	}

	/**
	 * @return the servletInfo
	 */
	public ServletInfo getServletInfo() {
		return servletInfo;
	}

	/**
	 * @param servletInfo
	 *            the servletInfo to set
	 */
	public void setServletInfo(ServletInfo servletInfo) {
		this.servletInfo = servletInfo;
	}

	/**
	 * @return the sourceString
	 */
	public String getSourceString() {
		return sourceString;
	}

	/**
	 * @param sourceString
	 *            the sourceString to set
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
	 * @param threadId
	 *            the threadId to set
	 */
	public void setThreadId(Long threadId) {
		this.threadId = threadId;
	}

	public ServletEventProcessor(Object firstElement, Object request, ServletInfo servletInfo, String sourceString,
			long threadId) {
		this.firstElement = firstElement;
		this.request = request;
		this.servletInfo = servletInfo;
		this.sourceString = sourceString;
		this.threadId = threadId;
	}

	@Override
	public void run() {
		try {
			if (IAgentConstants.TOMCAT_COYOTE_ADAPTER_PARSE_POST.equals(sourceString)) {
//				System.out.println("init servletInfo. " + servletInfo);
				if (firstElement != null) {
					ByteBuffer bb = null;
					// System.out.println("Inside coyote adapter for threadId " + this.threadId + "
					// source "+ this.sourceString);
					Field inputBufferField = firstElement.getClass().getDeclaredField("inputBuffer");
					inputBufferField.setAccessible(true);
					Object inputBuffer = inputBufferField.get(firstElement);

					for (Field field : inputBuffer.getClass().getDeclaredFields()) {
						String fieldName = field.getName();
						if (fieldName.equals("buf")) {
							Field bytes = inputBuffer.getClass().getDeclaredField("buf");
							bytes.setAccessible(true);
							bb = ByteBuffer.wrap((byte[]) bytes.get(inputBuffer)).duplicate();
							break;
						} else if (fieldName.equals("byteBuffer")) {
							Field bytes = inputBuffer.getClass().getDeclaredField("byteBuffer");
							bytes.setAccessible(true);
							bb = ((ByteBuffer) bytes.get(inputBuffer)).duplicate();
							break;
						}
					}
					Method getContentLength = firstElement.getClass().getMethod("getContentLength");
					int contentLength = (int) getContentLength.invoke(firstElement, null);
					servletInfo.setRawParameters(readByteBuffer(bb, contentLength));
				}
				if (request != null) {
					Method getQueryString = request.getClass().getMethod("getQueryString");
					Method getRemoteAddr = request.getClass().getMethod("getRemoteAddr");
					Method getMethod = request.getClass().getMethod("getMethod");
					Method getContentType = request.getClass().getMethod("getContentType");
					Method getRequestURI = request.getClass().getMethod("getRequestURI");

					// set all methods accessible
					getQueryString.setAccessible(true);
					getRemoteAddr.setAccessible(true);
					getMethod.setAccessible(true);
					getContentType.setAccessible(true);
					getRequestURI.setAccessible(true);

					servletInfo.setQueryString((String) getQueryString.invoke(request, null));
					servletInfo.setSourceIp((String) getRemoteAddr.invoke(request, null));
					servletInfo.setRequestMethod((String) getMethod.invoke(request, null));
					servletInfo.setContentType((String) getContentType.invoke(request, null));
					servletInfo.setRequestURI((String) getRequestURI.invoke(request, null));
				}
//				System.out.println("serrrr servletInfo. " + servletInfo);
				// System.out.println(
				// "Exiting coyote adapter for threadId " + this.threadId + " source " +
				// this.sourceString);
			} else if (IAgentConstants.TOMCAT_REQUEST_FACADE.equals(sourceString)) {
				Method getQueryString = request.getClass().getMethod("getQueryString");
				Method getRemoteAddr = request.getClass().getMethod("getRemoteAddr");
				Method getMethod = request.getClass().getMethod("getMethod");
				Method getContentType = request.getClass().getMethod("getContentType");
				Method getRequestURI = request.getClass().getMethod("getRequestURI");

				// set all methods accessible
				getQueryString.setAccessible(true);
				getRemoteAddr.setAccessible(true);
				getMethod.setAccessible(true);
				getContentType.setAccessible(true);
				getRequestURI.setAccessible(true);

				servletInfo.setQueryString((String) getQueryString.invoke(request, null));
				servletInfo.setSourceIp((String) getRemoteAddr.invoke(request, null));
				servletInfo.setRequestMethod((String) getMethod.invoke(request, null));
				servletInfo.setContentType((String) getContentType.invoke(request, null));
				servletInfo.setRequestURI((String) getRequestURI.invoke(request, null));
//				System.out.println("serrrr servletInfo. facade " + servletInfo);
			} else if (IAgentConstants.HTTP_SERVLET_SERVICE.equals(sourceString)
					|| IAgentConstants.FACES_SERVLET.equals(sourceString)
					|| IAgentConstants.STRUTS2_DO_FILTER.equals(sourceString)) {

				// System.out.println("Inside servlet for threadId " + this.threadId + " source
				// "+ this.sourceString);

				Method getQueryString = firstElement.getClass().getMethod("getQueryString");
				Method getRemoteAddr = firstElement.getClass().getMethod("getRemoteAddr");
				Method getMethod = firstElement.getClass().getMethod("getMethod");
				Method getContentType = firstElement.getClass().getMethod("getContentType");
				Method getRequestURI = firstElement.getClass().getMethod("getRequestURI");

				// set all methods accessible
				getQueryString.setAccessible(true);
				getRemoteAddr.setAccessible(true);
				getMethod.setAccessible(true);
				getContentType.setAccessible(true);
				getRequestURI.setAccessible(true);

				servletInfo.setQueryString((String) getQueryString.invoke(firstElement, null));
				servletInfo.setSourceIp((String) getRemoteAddr.invoke(firstElement, null));
				servletInfo.setRequestMethod((String) getMethod.invoke(firstElement, null));
				servletInfo.setContentType((String) getContentType.invoke(firstElement, null));
				servletInfo.setRequestURI((String) getRequestURI.invoke(firstElement, null));
				// System.out.println("Exiting servlet for threadId " + this.threadId + " source
				// "+ this.sourceString);

				// extract raw params if the request is from jetty
				// System.out.println("Request Class Name:" +
				// firstElement.getClass().getName());
				if (firstElement.getClass().getName().equals(IAgentConstants.JETTY_SERVLET_REQUEST_IDENTIFIER)) {
					// buffer located in request > _channel > _httpConnection > _requestBuffer

					ByteBuffer bb = null;

					Field channelField = firstElement.getClass().getDeclaredField("_channel");
					channelField.setAccessible(true);
					Object _channel = channelField.get(firstElement);

					Field httpConnectionField = _channel.getClass().getDeclaredField("_httpConnection");
					httpConnectionField.setAccessible(true);
					Object _httpConnection = httpConnectionField.get(_channel);

					Field bytes = _httpConnection.getClass().getDeclaredField("_requestBuffer");
					bytes.setAccessible(true);
					bb = (ByteBuffer) bytes.get(_httpConnection);

					Method getContentLength = firstElement.getClass().getMethod("getContentLength");
					int contentLength = (int) getContentLength.invoke(firstElement, null);
					servletInfo.setRawParameters(readByteBuffer(bb, contentLength));
				}

				// System.out.println("Current request map inside event processor : "+
				// LoggingInterceptor.requestMap);

			}
		} catch (Exception e) {
			// e.printStackTrace();
			// LoggingInterceptor.requestMap.remove(this.threadId);
			// System.out.println("Request map entry removed inside event processor for
			// threadID " + this.threadId + " source "+ this.sourceString);
			// System.out.println("Current request map inside event processor : "+
			// LoggingInterceptor.requestMap);
		}
	}

	private static String readByteBuffer(ByteBuffer buffer, int contentLength) {
		if (buffer == null) {
			return "";
		}
		int currPos = buffer.position();
		if (contentLength > 0 && (buffer.limit() - contentLength) > 0)
			buffer.position(buffer.limit() - contentLength);
		else
			return "";
		StringBuffer stringBuffer = new StringBuffer();
		while (buffer.remaining() > 0) {
			stringBuffer.append((char) buffer.get());
		}
		buffer.position(currPos);
		return stringBuffer.toString();
	}

	/**
	 * @return the request
	 */
	public Object getRequest() {
		return request;
	}

	/**
	 * @param request
	 *            the request to set
	 */
	public void setRequest(Object request) {
		this.request = request;
	}

}
