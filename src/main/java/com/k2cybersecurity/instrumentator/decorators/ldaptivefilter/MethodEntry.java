package com.k2cybersecurity.instrumentator.decorators.ldaptivefilter;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;
import org.apache.commons.lang3.StringUtils;

public class MethodEntry {
	
//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args, @Advice.This Object thisArg) {
        try {
        	String threadName = Thread.currentThread().getName();
        	if(StringUtils.startsWith(threadName, "K2-")) {
        		return;
        	}
            String executionId = ExecutionIDGenerator.getExecutionId();
            Callbacks.doOnEnter(signature, className, methodName, thisArg, args, executionId);
        } catch (Throwable e) {
//        	logger.log(LogLevel.ERROR, "Error: ", e, MethodEntry.class.getName());
        }
    }
}
