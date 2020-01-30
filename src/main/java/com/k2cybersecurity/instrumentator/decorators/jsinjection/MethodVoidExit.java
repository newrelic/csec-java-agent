package com.k2cybersecurity.instrumentator.decorators.jsinjection;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;
import org.apache.commons.lang3.StringUtils;

public class MethodVoidExit {
	
//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    @Advice.OnMethodExit(onThrowable = Exception.class)
    public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.Thrown Throwable error, @Advice.This Object thisArg, @Advice.AllArguments Object[] args) {
        try {
        	String threadName = Thread.currentThread().getName();
        	if(StringUtils.startsWith(threadName, "K2-")) {
        		return;
        	}
            String executionId = ExecutionIDGenerator.getExecutionId();
            if (error == null) {
                Callbacks.doOnExit(signature, className, methodName, thisArg, args, null, executionId);
            } else {
                Callbacks.doOnError(signature, className, methodName, thisArg, args, error, executionId);
            }
        } catch (Throwable e) {
//        	logger.log(LogLevel.ERROR, "Error: ", e, MethodVoidExit.class.getName());
        }
    }
}
