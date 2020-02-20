package com.k2cybersecurity.instrumentator.decorators.servletresponse;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPIOLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;

public class Callbacks {

    public static final String GET_WRITER = "getWriter";
    public static final String GET_OUTPUT_STREAM = "getOutputStream";
    public static final String INIT = "<init>";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
        System.out.println("Came to servletresponse hook :" + exectionId + " :: " + sourceString);
//        if (!ThreadLocalHttpMap.getInstance().isServiceMethodEncountered() && !ThreadLocalOperationLock.getInstance()
//                .isAcquired()) {
//            try {
//                ThreadLocalOperationLock.getInstance().acquire();
//                if (obj == null && args != null && args.length == 1 && args[0] != null) {
////                    System.out.println("Setting response  : " + exectionId);
//                    ThreadLocalHttpMap.getInstance().setHttpResponse(args[0]);
//                }
//            } finally {
//                ThreadLocalOperationLock.getInstance().release();
//            }
//        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (!ThreadLocalHttpMap.getInstance().isEmpty() && obj !=null && ThreadLocalHttpMap.getInstance().getHttpResponse()!=null && ThreadLocalHttpMap.getInstance().getHttpResponse().hashCode() == obj.hashCode()) {
                    System.out.println("Came to servletresponse hook exit :" + exectionId + " :: " + sourceString + " :: " + obj + " :: " + returnVal);
                    if (StringUtils.equals(methodName, GET_WRITER)) {
                        ThreadLocalHttpMap.getInstance().setResponseWriter(returnVal);
                        System.out.println("reponseWriter set kar diya. :" + exectionId + " :: " + ThreadLocalHttpMap.getInstance().getResponseWriter());
                        ThreadLocalHTTPIOLock.getInstance().resetLock();

                    } else if (StringUtils.equals(methodName, GET_OUTPUT_STREAM)) {
                        ThreadLocalHttpMap.getInstance().setResponseOutputStream(returnVal);
                        System.out.println("GET_OUTPUT_STREAM set kar diya. :" + exectionId + " :: " + ThreadLocalHttpMap.getInstance().getResponseWriter());
                        ThreadLocalHTTPIOLock.getInstance().resetLock();

                    }
                } else if(StringUtils.equals(methodName, INIT) && !ThreadLocalHttpMap.getInstance().isServiceMethodEncountered() && obj != null && CallbackUtils.checkArgsTypeHeirarchyResponse(obj)) {
                    System.out.println("Servlet response constructor exit aaya : "+ exectionId + " :: " + sourceString + " :: " + obj + " :: " + returnVal + " :: " + methodName);
                    ThreadLocalHttpMap.getInstance().setHttpResponse(obj);
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}
