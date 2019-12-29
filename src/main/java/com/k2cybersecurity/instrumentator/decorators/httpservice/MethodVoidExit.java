package com.k2cybersecurity.instrumentator.decorators.httpservice;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class MethodVoidExit {

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Origin String signature, @Advice.Thrown Throwable error, @Advice.This Object thisArg, @Advice.AllArguments Object[] args) throws Throwable {
        String executionId = ExecutionIDGenerator.getExecutionId();
        if(error == null){
            Callbacks.doOnExit(signature, thisArg, args, null, executionId);
        } else {
            Callbacks.doOnError(signature, thisArg, args, error, executionId);
        }
    }
}
