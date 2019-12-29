package com.k2cybersecurity.instrumentator.decorators.custom;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class StaticMethodExit {

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Origin String signature, @Advice.Return Object value, @Advice.Thrown Throwable error, @Advice.AllArguments Object[] args) {
        String executionId = ExecutionIDGenerator.getExecutionId();
        if(error == null){
            Callbacks.doOnExit(signature, null, args, value, executionId);
        } else {
            Callbacks.doOnError(signature, null, args, error, executionId);
        }
    }

}


