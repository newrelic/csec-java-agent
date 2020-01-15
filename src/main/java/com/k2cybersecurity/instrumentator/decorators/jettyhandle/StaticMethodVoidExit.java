package com.k2cybersecurity.instrumentator.decorators.jettyhandle;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;

import net.bytebuddy.asm.Advice;

public class StaticMethodVoidExit {
	
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    @Advice.OnMethodExit(onThrowable = Exception.class)
    public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.Thrown Throwable error, @Advice.AllArguments Object[] args) {
        String executionId = ExecutionIDGenerator.getExecutionId();
        try {
        	String threadName = Thread.currentThread().getName();
        	if(StringUtils.startsWith(threadName, "K2-")) {
        		return;
        	}
            if (error == null) {
                Callbacks.doOnExit(signature, className, methodName, null, args, null, executionId);
            } else {
                Callbacks.doOnError(signature, className, methodName, null, args, error, executionId);
            }
        } catch (Throwable e) {
        	logger.log(LogLevel.ERROR, "Error: ", e, StaticMethodVoidExit.class.getName());
        }
    }

}


