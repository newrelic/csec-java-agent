package com.k2cybersecurity.instrumentator.decorators.ssrf;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalSSRFLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.net.URL;
import java.time.Instant;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
        if (!ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalSSRFLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null) {
                    ThreadLocalSSRFLock.getInstance().acquire(obj, sourceString, exectionId);
                    Method getURL = obj.getClass().getMethod("getURL");
                    getURL.setAccessible(true);
                    URL url = (URL) getURL.invoke(obj);
                    String urlString = url.toString();

                    ThreadLocalSSRFLock.getInstance().setUrl(urlString);
                    Method setRequestProperty = obj.getClass().getMethod("setRequestProperty", String.class, String.class);
                    setRequestProperty.setAccessible(true);
                    setRequestProperty.invoke(obj, IAgentConstants.K2_API_CALLER, CallbackUtils.generateApiCallerHeaderValue(urlString));
                    if (StringUtils.equalsAny(url.getProtocol(), "http", "https")) {
//                        System.out.println(String.format("Entry : SSRF Value: %s : %s : %s : %s", className, methodName, obj, url.toString()));
                        EventDispatcher.dispatch(new SSRFOperationalBean(urlString, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.HTTP_REQUEST);
                    }
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) throws Exception {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println(String.format("Exit : SSRF Value: %s : %s : %s", className, methodName, obj));
//                Method getURL = obj.getClass().getMethod("getURL");
//                getURL.setAccessible(true);
//                URL url = (URL) getURL.invoke(obj);
//                OutBoundHttp outBoundHttp = new OutBoundHttp(url.toString(), K2Instrumentator.hostip, OutBoundHttpDirection.OUTBOUND);
//                if (!K2Instrumentator.JA_HEALTH_CHECK.getHttpConnections().contains(outBoundHttp)) {
//                    Object objToUse = obj;
//                    if (objToUse instanceof HttpsURLConnection) {
//                        Field delegate = objToUse.getClass().getDeclaredField("delegate");
//                        delegate.setAccessible(true);
//                        objToUse = delegate.get(objToUse);
//                    }
//
//                    if (objToUse instanceof HttpURLConnection) {
//                        Field httpField = HttpURLConnection.class.getDeclaredField("http");
//                        httpField.setAccessible(true);
//                        HttpClient client = (HttpClient) httpField.get(objToUse);
//                        Field serverSocketField = NetworkClient.class.getDeclaredField("serverSocket");
//                        serverSocketField.setAccessible(true);
//                        Socket socket = (Socket) serverSocketField.get(client);
//                        outBoundHttp.setDestinationIp(socket.getInetAddress().getHostAddress());
//                        outBoundHttp.setDestinationPort(socket.getPort());
//                        outBoundHttp.setSourcePort(socket.getLocalPort());
//                        K2Instrumentator.JA_HEALTH_CHECK.getHttpConnections().add(outBoundHttp);
//                    }
//                }

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
                && ThreadLocalSSRFLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Error : SSRF Value: %s : %s : %s", className, methodName, obj));

//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
                ThreadLocalSSRFLock.getInstance().release(obj, sourceString, exectionId);
            }
        }
    }
}
