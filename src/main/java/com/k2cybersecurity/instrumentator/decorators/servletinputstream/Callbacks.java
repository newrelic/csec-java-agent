package com.k2cybersecurity.instrumentator.decorators.servletinputstream;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPIOLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

public class Callbacks {

    public static final String READ = "read";
    public static final String INSERTING_TO_REQUEST = "Inserting to request : ";
    public static final String READ_LINE = "readLine";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
//        System.out.println("OnEnter servletinputstream :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && ThreadLocalHttpMap.getInstance().getRequestInputStream() != null && obj != null && ThreadLocalHttpMap.getInstance().getRequestInputStream().hashCode() == obj.hashCode()) {
            if (!ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalHTTPIOLock.getInstance().isAcquired()) {
                try {
                    ThreadLocalOperationLock.getInstance().acquire();
                    ThreadLocalHTTPIOLock.getInstance().acquire(obj, sourceString, exectionId);
                } finally {
                    ThreadLocalOperationLock.getInstance().release();
                }
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
//        System.out.println("OnExit servletinputstream :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj.hashCode() + " - return : " + returnVal + " - eid : " + exectionId);

        if (!ThreadLocalHttpMap.getInstance().isEmpty() && ThreadLocalHttpMap.getInstance().getRequestInputStream() != null && obj != null && ThreadLocalHttpMap.getInstance().getRequestInputStream().hashCode() == obj.hashCode() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            if (ThreadLocalHTTPIOLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
                try {
                    ThreadLocalOperationLock.getInstance().acquire();
//                    System.out.println("servletinputstream ke read me aaya :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

                    switch (methodName) {
                        case READ:
                            if ((args == null || args.length == 0) && returnVal instanceof Integer) {
//                                System.out.println(INSERTING_TO_REQUEST + args[0] + " :: " + obj.hashCode());
                                if ((int) returnVal != -1)
                                    ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(new Integer((int) returnVal).byteValue());
                            } else if (args != null && args.length == 1 && args[0] instanceof byte[] && (int) returnVal != -1) {
//                                System.out.println("Inserting to request : " + args[0] + " :: " + obj.hashCode());
                                ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer((byte[]) args[0], 0, (int) returnVal);
                            } else if (args != null && args.length == 3 && args[0] instanceof byte[] && (int) returnVal != -1) {
//                                System.out.println("Inserting to request : " + args[0] + " :: " + obj.hashCode());
                                ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer((byte[]) args[0], (int) args[1], (int) returnVal);
                            }
                            break;
                        case READ_LINE:
                            if (args != null && args.length == 3 && args[0] instanceof byte[] && (int) returnVal != -1) {
//                                System.out.println("Inserting to request : " + args[0] + " :: " + obj.hashCode());
                                ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer((byte[]) args[0], (int) args[1], (int) returnVal);
                            }
                            break;
                    }

                    //					System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
                } finally {
                    ThreadLocalHTTPIOLock.getInstance().release(obj, sourceString, exectionId);
                    ThreadLocalOperationLock.getInstance().release();
                }
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalHTTPIOLock.getInstance().release(obj, sourceString, exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}
