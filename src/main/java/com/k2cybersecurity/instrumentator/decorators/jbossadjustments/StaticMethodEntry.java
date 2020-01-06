package com.k2cybersecurity.instrumentator.decorators.jbossadjustments;

import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class StaticMethodEntry {

    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args) {
        try {
            String executionId = ExecutionIDGenerator.getExecutionId();
            Callbacks.doOnEnter(signature, className, methodName, null, args, executionId);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}


