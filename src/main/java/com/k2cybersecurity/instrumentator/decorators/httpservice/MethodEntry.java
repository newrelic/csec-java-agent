package com.k2cybersecurity.instrumentator.decorators.httpservice;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class MethodEntry {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin String signature, @Advice.AllArguments Object[] args, @Advice.This Object thisArg) {
        String executionId = ExecutionIDGenerator.getExecutionId();
        Callbacks.doOnEnter(signature, thisArg, args, executionId);

    }
}
