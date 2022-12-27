package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

public final class SecurityApiClassTransformer implements ClassFileTransformer {

    private static final String NEW_RELIC_SECURITY_CLASS = StringUtils.replace(SecurityInstrumentationTestRunner.NEW_RELIC_SECURITY_CLASS, ".", "/");

    private static final String AGENT_CLASS = StringUtils.replace(SecurityInstrumentationTestRunner.AGENT_CLASS, ".", "/");

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {

        if (className == null) {
            return classfileBuffer;
        }
        try {

            if (NEW_RELIC_SECURITY_CLASS.equals(className)) {
                return SecurityInstrumentationTestRunner.nrSecurityClassResource.read();
            }

            if (AGENT_CLASS.equals(className)) {
                return SecurityInstrumentationTestRunner.agentClassResource.read();
            }

//            if (loader == null && StringUtils.startsWith(className, "com/newrelic")){
//                System.out.println();
//            }
        } catch (IOException ignored) {
            ignored.printStackTrace();
        }
        return classfileBuffer;
    }
}