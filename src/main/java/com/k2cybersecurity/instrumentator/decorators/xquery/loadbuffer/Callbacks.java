package com.k2cybersecurity.instrumentator.decorators.xquery.loadbuffer;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalXQuerySaxonMap;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;

import java.lang.reflect.Field;

public class Callbacks {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String executionId) {

//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				System.out.println(
//						"sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + obj);
//				ThreadLocalOperationLock.getInstance().acquire();
//				
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object thisObject,
                                Object[] args, Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : "
//						+ thisObject + " - return : " + returnVal + " - eid : " + exectionId);
                if (ThreadLocalXQuerySaxonMap.getInstance().isCompileStartMarked()) {
                    try {
                        Field lengthField = thisObject.getClass().getSuperclass().getDeclaredField("n");
                        lengthField.setAccessible(true);
                        int length = (int) lengthField.get(thisObject);
//						System.out.println("Length : " + length);
                        if (length != 0) {
                            Field dataField = thisObject.getClass().getSuperclass().getDeclaredField("data");
                            dataField.setAccessible(true);
                            Object dataObject = dataField.get(thisObject);
                            String data = new String((char[]) dataObject, 0, length - 1);
//							System.out.println("Data : " + data);
                            ThreadLocalXQuerySaxonMap.getInstance().setTempBuffer(data);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
    }
}
