package com.k2cybersecurity.instrumentator.decorators.crypto;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class StaticMethodVoidExit {

    @Advice.OnMethodExit(onThrowable = Exception.class)
    public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.Thrown Throwable error, @Advice.AllArguments Object[] args) {
        String executionId = ExecutionIDGenerator.getExecutionId();
        try {
            if (error == null) {
                Callbacks.doOnExit(signature, className, methodName, null, args, null, executionId);
            } else {
                Callbacks.doOnError(signature, className, methodName, null, args, error, executionId);
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}


