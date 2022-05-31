package com.k2cybersecurity.instrumentator.decorators.outboundhttp.socket;

import com.k2cybersecurity.instrumentator.custom.*;
import com.k2cybersecurity.intcodeagent.models.javaagent.OutBoundHttp;
import com.k2cybersecurity.intcodeagent.models.javaagent.OutBoundHttpDirection;
import com.k2cybersecurity.intcodeagent.schedulers.InBoundOutBoundST;

import java.net.Socket;

public class Callbacks {

    public static final String SOURCE_IP_ALL = "0.0.0.0";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
//		System.out.println(String.format("Entry : Socket : %s : %s : %s : %s", className, methodName, sourceString, exectionId));
        if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && !ThreadLocalOperationLock.getInstance().isAcquired() && ThreadLocalSSRFLock.getInstance().isAcquired()) {
//			System.out.println(String.format("Entry OL is available : SSRF : %s : %s : %s", className, methodName, sourceString));

            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(String.format("Entry OL acquired : SSRF : %s : %s : %s", className, methodName, sourceString));
//				System.out.println(String.format("Args : %s : SSRF : %s : %s : %s", Arrays.asList(args), className, methodName, sourceString));


                Socket socket = (Socket) obj;
                OutBoundHttp outBoundHttp = new OutBoundHttp(ThreadLocalSSRFLock.getInstance().getUrl(), SOURCE_IP_ALL, socket.getInetAddress().getHostAddress(), OutBoundHttpDirection.OUTBOUND, null);
                outBoundHttp.setDestinationPort(socket.getPort());
//				outBoundHttp.setSourcePort(socket.getLocalPort());
                if (!ThreadLocalSSRFMap.getInstance().isAlreadyEncountered(outBoundHttp)) {
                    ThreadLocalSSRFMap.getInstance().addToAlreadyEncountered(outBoundHttp);
                    InBoundOutBoundST.getInstance().addOutBoundHTTPConnection(outBoundHttp);
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
//        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//            try {
//                ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println(String.format("Exit : SSRF : %s : %s", className, methodName));
//
////				System.out.println(
////						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
////								+ returnVal + " - eid : " + exectionId);
//            } finally {
//                ThreadLocalOperationLock.getInstance().release();
//            }
//        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
//        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//            try {
//                ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println(String.format("Error : SSRF : %s : %s", className, methodName));
//
////				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////						+ " - error : " + error + " - eid : " + exectionId);
//            } finally {
//                ThreadLocalOperationLock.getInstance().release();
//            }
//        }
    }
}
