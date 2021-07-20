package com.k2cybersecurity.instrumentator.custom;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.build.HashCodeAndEqualsPlugin;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.bytecode.StackManipulation;
import net.bytebuddy.implementation.bytecode.member.MethodInvocation;

@HashCodeAndEqualsPlugin.Enhance
public class K2ExceptionHandler {

    public static enum Handler implements Advice.ExceptionHandler {
        LOG {
            @Override
            public StackManipulation resolve(MethodDescription methodDescription, TypeDescription typeDescription) {
                try {
//					return Removal.ZERO;
                    return MethodInvocation.invoke(new MethodDescription.ForLoadedMethod(Throwable.class.getMethod("printStackTrace")));
                } catch (Exception var4) {
                    throw new IllegalStateException("Cannot locate Throwable::printStackTrace");
                }
            }
        }
    }

}
