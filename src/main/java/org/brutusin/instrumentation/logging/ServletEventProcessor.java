package org.brutusin.instrumentation.logging;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.fasterxml.jackson.databind.ObjectMapper;

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
				// System.out.println("init servletInfo. " + servletInfo);
				if (firstElement != null) {
					byte[] bb = null;
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
							bb = (byte[]) bytes.get(inputBuffer);
							break;
						} else if (fieldName.equals("byteBuffer")) {
							Field bytes = inputBuffer.getClass().getDeclaredField("byteBuffer");
							bytes.setAccessible(true);
							Object byteBuffer = (ByteBuffer)bytes.get(inputBuffer);
							System.out.println("fields of byteBuffer : " + byteBuffer.getClass().getName() + " : "+ Arrays.asList(ByteBuffer.class.getFields()) + " : " + Arrays.asList(ByteBuffer.class.getDeclaredFields()));
							System.out.println("RAW fields of byteBuffer : " + byteBuffer.getClass().getName() + " : "+ ByteBuffer.class.getFields() + " : " + ByteBuffer.class.getDeclaredFields());

							Field hb = ByteBuffer.class.getDeclaredField("hb");
							hb.setAccessible(true);
							bb = (byte[]) hb.get(byteBuffer);
							break;
						}
					}
					Method getContentLength = firstElement.getClass().getMethod("getContentLength");
					int contentLength = (int) getContentLength.invoke(firstElement, null);
					servletInfo.setRawParameters(readBytes(bb));
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
				// System.out.println("serrrr servletInfo. " + servletInfo);
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
				// System.out.println("serrrr servletInfo. facade " + servletInfo);
			}
		} catch (Exception e) {
			e.printStackTrace();
			// LoggingInterceptor.requestMap.remove(this.threadId);
			// System.out.println("Request map entry removed inside event processor for
			// threadID " + this.threadId + " source "+ this.sourceString);
			// System.out.println("Current request map inside event processor : "+
			// LoggingInterceptor.requestMap);

		}
	}

	private static String readByteBuffer(ByteBuffer buffer, int contentLength) {
		if (buffer == null)
			return "";
		int currPos = buffer.position();
		buffer.position(0);
		buffer.limit(contentLength);
//		int currPos = buffer.position();
//		if (contentLength > 0 && (buffer.capacity() - contentLength) > 0)
//			buffer.position(buffer.capacity() - contentLength);
//		else
//			return "";
		StringBuffer stringBuffer = new StringBuffer();
		while (buffer.remaining() > 0) {
			stringBuffer.append((char) buffer.get());
		}
		buffer.position(currPos);
		return stringBuffer.toString();
	}
	
	private static String readBytes(byte[] bytes) {
		if (bytes == null)
			return "";
		StringBuffer stringBuffer = new StringBuffer();
		for(int i = 0 ; i< bytes.length; i++) {
			if(bytes[i] == 0)
				break;
			stringBuffer.append((char) bytes[i]);
		}
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
