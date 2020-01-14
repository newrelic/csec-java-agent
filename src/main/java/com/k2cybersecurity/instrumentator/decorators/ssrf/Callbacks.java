package com.k2cybersecurity.instrumentator.decorators.ssrf;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.time.Instant;

import static com.k2cybersecurity.instrumentator.decorators.ssrf.ISSRFConstants.*;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
			String exectionId) {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - eid : " + exectionId);
				Object[] newArgs;
				if(args != null) {
					newArgs = new Object[args.length + 1];
					for(int i =0 ; i< args.length; i++){
						newArgs[i] = args[i];
					}
					newArgs[newArgs.length-1] = obj;
				} else {
					newArgs = new Object[] {obj};
				}
				EventDispatcher.dispatch(new SSRFOperationalBean(newArgs, className, sourceString, exectionId,
						Instant.now().toEpochMilli()), VulnerabilityCaseType.HTTP_REQUEST);

			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static Object[] getApacheCommonsHttpRequestParameters(Object[] object) {
		Object[] argArray = new Object[2];
		Object httpMethod = object[0];
		try {
			Class<?> httpMethodInterface;
			Class<?> httpURI;
			ClassLoader httpMethodLoader = httpMethod.getClass().getClassLoader();
			if (httpMethodLoader != null) {
				httpMethodInterface = Class.forName(ORG_APACHE_COMMONS_HTTPCLIENT_HTTP_METHOD, true, httpMethodLoader);
				httpURI = Class.forName(ORG_APACHE_COMMONS_HTTPCLIENT_URI, true, httpMethodLoader);
			} else {
				httpMethodInterface = Class.forName(ORG_APACHE_COMMONS_HTTPCLIENT_HTTP_METHOD, true,
						Thread.currentThread().getContextClassLoader());
				httpURI = Class.forName(ORG_APACHE_COMMONS_HTTPCLIENT_URI, true,
						Thread.currentThread().getContextClassLoader());
			}
			Method getURI = httpMethodInterface.getMethod(GET_URI);
			Object uri = getURI.invoke(httpMethod);

			Method getHost = httpURI.getMethod(GET_HOST);
			String host = (String) getHost.invoke(uri);

			Method getPath = httpURI.getMethod(GET_PATH);
			String path = (String) getPath.invoke(uri);

			argArray[0] = host;
			argArray[0] = path;

		} catch (Exception e) {
		}
		return argArray;
	}

	public static Object[] getJava9HttpClientParameters(Object[] obj) {
		Object[] argArray = new Object[2];
		Object multiExchangeObj = obj;
		try {
			Class<?> multiExchangeClass = Thread.currentThread().getContextClassLoader()
					.loadClass(JDK_INCUBATOR_HTTP_MULTI_EXCHANGE);
			Field request = multiExchangeClass.getDeclaredField(FIELD_REQUEST);
			request.setAccessible(true);
			Object httpReqObj = request.get(multiExchangeObj);

			Field uri = httpReqObj.getClass().getDeclaredField(FIELD_URI);
			uri.setAccessible(true);
			URI uriObj = (URI) uri.get(httpReqObj);
			argArray[0] = uriObj.getHost();
			argArray[1] = uriObj.getPath();

		} catch (Exception e) {
			e.printStackTrace();
		}
		return argArray;
	}

	public static Object[] getApacheHttpRequestParameters(Object[] object) {
		Object[] argArray = new Object[2];
		Object request = object[0];
		Object httpContext = object[2];
		try {
			Class<?> httpClientInterface;
			Class<?> httpContextInterface;
			ClassLoader requestLoader = request.getClass().getClassLoader();
			ClassLoader httpContextLoader = httpContext.getClass().getClassLoader();
			if (requestLoader != null) {
				httpClientInterface = Class.forName(ORG_APACHE_HTTP_HTTP_REQUEST, true, requestLoader);
			} else {
				httpClientInterface = Class.forName(ORG_APACHE_HTTP_HTTP_REQUEST, true,
						Thread.currentThread().getContextClassLoader());
			}

			if (httpContextLoader != null) {
				httpContextInterface = Class.forName(ORG_APACHE_HTTP_PROTOCOL_HTTP_CONTEXT, true, httpContextLoader);
			} else {
				httpContextInterface = Class.forName(ORG_APACHE_HTTP_PROTOCOL_HTTP_CONTEXT, true,
						Thread.currentThread().getContextClassLoader());
			}
			Method getRequestLine = httpClientInterface.getMethod(GET_REQUEST_LINE);
			Object requestLine = getRequestLine.invoke(request);

			String requestLineStr = requestLine.toString();
			String[] requestLineTokens = requestLineStr.split(REGEX_SPACE);
			String requestUri = requestLineTokens[1];
			Method getAttribute = httpContextInterface.getMethod(GET_ATTRIBUTE, String.class);
			Object attributeHost = getAttribute.invoke(httpContext, HTTP_TARGET_HOST);

			int indexOfQmark = requestUri.indexOf('?');
			// means request param is present
			String pathOnly = EMPTY;
			if (indexOfQmark != -1) {
				pathOnly = requestUri.substring(0, indexOfQmark);
			}

			argArray[0] = attributeHost.toString();
			argArray[1] = pathOnly;

		} catch (Exception e) {
		}
		return argArray;

	}

	public static Object[] getOkHttpRequestParameters(Object[] object) {
		Object[] argArray = new Object[2];
		Object httpEngine = object[0];
		try {
			Method getRequest = httpEngine.getClass().getMethod(METHOD_GET_REQUEST);
			Object request = getRequest.invoke(httpEngine);

			Field httpUrl = request.getClass().getDeclaredField(FIELD_URL);
			httpUrl.setAccessible(true);
			Object httpUrlObj = httpUrl.get(request);

			Method getUrl = httpUrlObj.getClass().getMethod(FIELD_URL);
			URL url = (URL) getUrl.invoke(httpUrlObj);

			argArray[0] = url.getHost();
			argArray[1] = url.getPath();

		} catch (Exception e) {
		}
		return argArray;
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
//		if(!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(
//						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
//								+ returnVal + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}
}
