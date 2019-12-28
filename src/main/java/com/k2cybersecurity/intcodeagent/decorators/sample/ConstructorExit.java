package com.k2cybersecurity.intcodeagent.decorators.sample;

import com.k2cybersecurity.intcodeagent.utils.instrumentation.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class ConstructorExit {

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin String signature, @Advice.AllArguments Object[] args){
        String executionId = ExecutionIDGenerator.getExecutionId();
        Callbacks.doOnExit(signature, null, args, null, executionId);
    }

}


