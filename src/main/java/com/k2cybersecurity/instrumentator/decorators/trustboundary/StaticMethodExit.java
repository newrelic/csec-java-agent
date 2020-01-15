package com.k2cybersecurity.instrumentator.decorators.trustboundary;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

public class StaticMethodExit {
	
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    @Advice.OnMethodExit(onThrowable = Exception.class)
    public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object value, @Advice.Thrown Throwable error, @Advice.AllArguments Object[] args) {
        try {
        	String threadName = Thread.currentThread().getName();
        	if(StringUtils.startsWith(threadName, "K2-")) {
        		return;
        	}
            String executionId = ExecutionIDGenerator.getExecutionId();
            if (error == null) {
                Callbacks.doOnExit(signature, className, methodName, null, args, value, executionId);
            } else {
                Callbacks.doOnError(signature, className, methodName, null, args, error, executionId);
            }
        } catch (Throwable e) {
        	logger.log(LogLevel.ERROR, "Error: ", e, StaticMethodExit.class.getName());
        }
    }

}


