package com.k2cybersecurity.instrumentator.decorators.fileaccess;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class MethodVoidExit {

    @Advice.OnMethodExit(onThrowable = Exception.class)
    public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.Thrown Throwable error, @Advice.This Object thisArg, @Advice.AllArguments Object[] args) {
        try {
            String executionId = ExecutionIDGenerator.getExecutionId();
            if (error == null) {
                Callbacks.doOnExit(signature, className, methodName, thisArg, args, null, executionId);
            } else {
                Callbacks.doOnError(signature, className, methodName, thisArg, args, error, executionId);
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
