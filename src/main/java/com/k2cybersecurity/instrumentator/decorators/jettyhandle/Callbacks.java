package com.k2cybersecurity.instrumentator.decorators.jettyhandle;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args, String exectionId) {
//        System.out.println("OnEnter :" + sourceString + " - this : " + obj + " - eid : " + exectionId);

        // TODO: Need more checks here to assert the type of args. Maybe the TYPE_BASED hook advice should be generated from Code with very specific checks.
        //  Doing checks here will degrade performance.
        if (args != null && args.length == 4) {
            ThreadLocalHttpMap.getInstance().setHttpRequest(args[2]);
            ThreadLocalHttpMap.getInstance().setHttpResponse(args[3]);
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args, Object returnVal, String exectionId) {
//        System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

//        ThreadLocalHttpMap.getInstance().parseHttpRequest();
        ThreadLocalHttpMap.getInstance().cleanState();
        ThreadLocalDBMap.getInstance().clearAll();
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args, Throwable error, String exectionId) throws Throwable {
        System.out.println("OnError :" + sourceString + " - this : " + obj + " - error : " + error + " - eid : " + exectionId);
        ThreadLocalHttpMap.getInstance().cleanState();
        ThreadLocalDBMap.getInstance().clearAll();
    }
}
