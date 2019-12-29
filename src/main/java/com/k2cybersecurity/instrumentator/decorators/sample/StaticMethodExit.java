package com.k2cybersecurity.instrumentator.decorators.sample;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

public class StaticMethodExit {

    @Advice.OnMethodExit(onThrowable = Exception.class)
    public static void exit(@Advice.Origin String signature, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object value, @Advice.Thrown Throwable error, @Advice.AllArguments Object[] args) {
        try {
            String executionId = ExecutionIDGenerator.getExecutionId();
            if (error == null) {
                Callbacks.doOnExit(signature, null, args, value, executionId);
            } else {
                Callbacks.doOnError(signature, null, args, error, executionId);
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}


