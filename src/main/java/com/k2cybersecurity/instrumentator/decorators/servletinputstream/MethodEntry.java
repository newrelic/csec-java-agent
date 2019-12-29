package com.k2cybersecurity.instrumentator.decorators.servletinputstream;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class MethodEntry {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin String signature, @Advice.AllArguments Object[] args, @Advice.This Object thisArg) {
        try {
            String executionId = ExecutionIDGenerator.getExecutionId();
            Callbacks.doOnEnter(signature, thisArg, args, executionId);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
