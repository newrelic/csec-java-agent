/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.net.URLClassLoader;
import java.security.ProtectionDomain;

/**
 * ClassLoader that intercepts class loads, allowing classes to be transformed.
 */
class TransformingClassLoader extends URLClassLoader {
    private static final String[] ALLOWED_PREFIXES = new String[]{"com.sun.jersey", "java.net",
            "java.lang.ProcessImpl", "java.io", "java.nio"
    };
    private static final String[] PROTECTED_PREFIXES = new String[]{"java.", "javax.", "com.sun.", "sun.",
            "org.junit.", "junit.framework", "com.newrelic", "org.xml", "org.w3c"};

    private static final String[] INTROSPECTOR_MUST_LOADS = new String[]{
            // This class needs to be woven.
            "com.newrelic.agent.security.introspec.internal.HttpTestServerImpl",

            // These classes both trigger the HttpTestServerImpl to get loaded
            "com.newrelic.agent.security.introspec.internal.HttpServerRule",
            "com.newrelic.agent.security.introspec.internal.HttpServerLocator",
            "com.newrelic.api.agent.security.NewRelicSecurity"
    };

    public TransformingClassLoader(URLClassLoader parent) {
        super(parent.getURLs(), parent);

        try {
            // We need these classes to be loaded by this classloader.
            for (String mustLoadClassName : INTROSPECTOR_MUST_LOADS) {
                this.loadClass(mustLoadClassName, true);
            }
        } catch (ClassNotFoundException e) {
        }
    }

    protected boolean canTransform(String className) {
        for (String mustLoadClassPrefix : INTROSPECTOR_MUST_LOADS) {
            if (className.startsWith(mustLoadClassPrefix)) {
                return true;
            }
        }
        for (String prefix : ALLOWED_PREFIXES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        for (String prefix : PROTECTED_PREFIXES) {
            if (className.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public final Class<?> loadClass(String className) throws ClassNotFoundException {

        if (canTransform(className)) {
            Class<?> alreadyLoadedClass = findLoadedClass(className);
            if (alreadyLoadedClass != null) {
                return alreadyLoadedClass;
            }

            try {
                byte[] transformedBytes = transform(className);
                if (transformedBytes != null && !StringUtils.startsWith(className, "java.")) {
                    return defineClass(className, transformedBytes, 0, transformedBytes.length);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return findClass(className);
        }
        return super.loadClass(className);
    }

    private Class<?> directDefineClass(String className, byte[] transformedBytes) {
        Class<?> retClass = null;
        try {
            Method defineClass1 = ClassLoader.class.getDeclaredMethod("defineClass1", String.class, byte[].class, int.class, int.class,
                    ProtectionDomain.class, String.class);
            defineClass1.setAccessible(true);
            retClass = (Class<?>) defineClass1.invoke(this, className, transformedBytes, 0, transformedBytes.length, null, null);
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return retClass;
    }

    private Class<?> findAlreadyLoadedClass(String className) {
        for (Class loadedClass : SecurityInstrumentationTestRunner.instrumentation.getAllLoadedClasses()) {
            if (StringUtils.equals(loadedClass.getName(), className)) {
                return loadedClass;
            }
        }
        return null;
    }

    protected byte[] transform(String className) throws Exception {
        return null;
    }
}
