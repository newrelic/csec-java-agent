package com.k2cybersecurity.instrumentator.decorators.ssrf.akkahttp10;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalSSRFLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;

import java.lang.reflect.Method;
import java.net.URL;
import java.time.Instant;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
        if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && !ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalSSRFLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (args != null &&
                        args.length > 1 && args[0] != null
                ) {
                    ThreadLocalSSRFLock.getInstance().acquire(obj, sourceString, exectionId);
                    Method getUri = args[0].getClass().getMethod("getUri");
                    getUri.setAccessible(true);
                    Object uri = getUri.invoke(args[0]);

                    Method getScheme = uri.getClass().getMethod("getScheme");
                    getScheme.setAccessible(true);
                    Method getHost = uri.getClass().getMethod("getHost");
                    getHost.setAccessible(true);
                    Method getPort = uri.getClass().getMethod("getPort");
                    getPort.setAccessible(true);
                    Method getPathString = uri.getClass().getMethod("getPathString");
                    getPathString.setAccessible(true);

                    URL url = new URL(getScheme.invoke(uri).toString(),
                            getHost.invoke(uri).toString(),
                            (int) getPort.invoke(uri),
                            getPathString.invoke(uri).toString());

                    System.out.println(String.format("Entry : SSRF : %s : %s : %s : %s", className, methodName, sourceString, exectionId));
                    ThreadLocalSSRFLock.getInstance().setUrl(url.toString());

                    EventDispatcher.dispatch(new SSRFOperationalBean(url.toString(), className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.HTTP_REQUEST);

                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
//        		System.out.println(String.format("Exit : SSRF : %s : %s : %s : %s", className, methodName, sourceString, obj));
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)
        ) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(
//						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
//								+ returnVal + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
                ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);

            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)
        ) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
                ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);

            }
        }
    }
}
