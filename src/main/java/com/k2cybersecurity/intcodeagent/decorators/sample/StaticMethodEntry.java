package com.k2cybersecurity.intcodeagent.decorators.sample;

import com.k2cybersecurity.intcodeagent.utils.instrumentation.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;

public class StaticMethodEntry {

    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin String signature, @Advice.AllArguments Object[] args) {
        String executionId = ExecutionIDGenerator.getExecutionId();
        Callbacks.doOnEnter(signature, null, args, executionId);
    }

}


