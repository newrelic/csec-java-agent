package com.k2cybersecurity.intcodeagent.decorators.sample;

import com.k2cybersecurity.intcodeagent.utils.instrumentation.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class MethodVoidExit {

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Origin String signature, @Advice.Thrown Throwable error, @Advice.This Object thisArg, @Advice.AllArguments Object[] args) {
        String executionId = ExecutionIDGenerator.getExecutionId();
        if(error == null){
            Callbacks
					.doOnExit(signature, thisArg, args, null, executionId);
        } else {
            Callbacks
					.doOnError(signature, thisArg, args, error, executionId);
        }
    }
}
