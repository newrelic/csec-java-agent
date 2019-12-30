package com.k2cybersecurity.instrumentator.decorators.httpservice;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class MethodEntry {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args, @Advice.This Object thisArg) {
        try {
            String executionId = ExecutionIDGenerator.getExecutionId();
            Callbacks.doOnEnter(signature, className, methodName, thisArg, args, executionId);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
