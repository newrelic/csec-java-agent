package com.k2cybersecurity.instrumentator.decorators.servletoutputstream;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;
import org.apache.commons.lang3.StringUtils;

public class ConstructorExit {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	
    @Advice.OnMethodExit
    public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args, @Advice.This Object thisObject) {
        try {
        	String threadName = Thread.currentThread().getName();
        	if(StringUtils.startsWith(threadName, "K2-")) {
        		return;
        	}
            String executionId = ExecutionIDGenerator.getExecutionId();
            Callbacks.doOnExit(signature, className, methodName, thisObject, args, null, executionId);
        } catch (Throwable e) {
//        	logger.log(LogLevel.ERROR, "Error: ", e, ConstructorExit.class.getName());
        }
    }
}


