package com.k2cybersecurity.instrumentator.decorators.servletinputstream;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;

import java.util.Arrays;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args, String exectionId) {
        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args, Object returnVal, String exectionId) {
        if (args != null && args.length == 1) {
            ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(Arrays.copyOfRange((byte[]) args[0], 0, (Integer) returnVal));
        } else if (args != null && args.length == 3) {
            ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(Arrays.copyOfRange((byte[]) args[0], (Integer) args[1], (Integer) args[2]));
        } else if (args == null || args.length == 0) {
            ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(((Integer) returnVal).byteValue());
        }
        System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args, Throwable error, String exectionId) throws Throwable {
        System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - error : " + error + " - eid : " + exectionId);
    }
}
