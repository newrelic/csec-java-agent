package com.k2cybersecurity.instrumentator.decorators.ldap;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;

import net.bytebuddy.asm.Advice;

public class MethodEntry {
	
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	
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
        	logger.log(LogLevel.ERROR, "Error: ", e, MethodEntry.class.getName());
        }
    }
}
