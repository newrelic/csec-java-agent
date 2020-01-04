package com.k2cybersecurity.instrumentator.decorators.httpservice;

import java.io.File;
import java.time.Instant;
import java.util.Map;
import java.util.Map.Entry;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args, String exectionId) {
//        System.out.println("OnEnter :" + sourceString + " - this : " + obj + " - eid : " + exectionId);

        // TODO: Need more checks here to assert the type of args. Maybe the TYPE_BASED hook advice should be generated from Code with very specific checks.
        //  Doing checks here will degrade performance.
        if (args != null && args.length == 2) {
            ThreadLocalHttpMap.getInstance().setHttpRequest(args[0]);
            ThreadLocalHttpMap.getInstance().setHttpResponse(args[1]);
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args, Object returnVal, String exectionId) {
//        System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

//        ThreadLocalHttpMap.getInstance().parseHttpRequest();
        onHttpTermination();
        
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args, Throwable error, String exectionId) throws Throwable {
        System.out.println("OnError :" + sourceString + " - this : " + obj + " - error : " + error + " - eid : " + exectionId);
        onHttpTermination();
    }
    
    private static void onHttpTermination() {
    	ThreadLocalHttpMap.getInstance().cleanState();
        ThreadLocalDBMap.getInstance().clearAll();
        CallbackUtils.checkForFileIntegrity(ThreadLocalExecutionMap.getInstance().getFileLocalMap());
        ThreadLocalExecutionMap.getInstance().getFileLocalMap().clear();
	}

	
}
