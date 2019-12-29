package com.k2cybersecurity.instrumentator.decorators.httpservice;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.bytecode.StackManipulation;

public class ExceptionThrowhandler implements Advice.ExceptionHandler {

    @Override
    public StackManipulation resolve(MethodDescription methodDescription, TypeDescription typeDescription) {
        return null;
    }
}
