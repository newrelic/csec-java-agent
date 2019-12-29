package com.k2cybersecurity.instrumentator.decorators.sample;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class ConstructorExit {

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin String signature, @Advice.AllArguments Object[] args) {
        try {
            String executionId = ExecutionIDGenerator.getExecutionId();
            Callbacks.doOnExit(signature, null, args, null, executionId);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}


