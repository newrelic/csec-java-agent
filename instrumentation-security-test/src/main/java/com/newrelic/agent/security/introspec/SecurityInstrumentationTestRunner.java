/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.introspec;

import com.newrelic.agent.instrumentation.weaver.preprocessors.TracedWeaveInstrumentationTracker;
import com.newrelic.agent.security.introspec.internal.*;
import com.newrelic.weave.weavepackage.WeavePackageManager;
import org.apache.commons.lang3.StringUtils;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.jar.JarFile;

public final class SecurityInstrumentationTestRunner extends BlockJUnit4ClassRunner {

    public static final String NEW_RELIC_SECURITY_CLASS = "com.newrelic.api.agent.security.NewRelicSecurity";
    public static final String AGENT_CLASS = "com.newrelic.api.agent.security.Agent";
    private final Map<String, Object> configOverrides;

    public static Instrumentation instrumentation;

    public static WeavePackageManager weavePackageManager;
    public static ClassLoader instrumentingClassloader;
    public static ConcurrentMap<String, Set<TracedWeaveInstrumentationTracker>> tracedWeaveInstrumentationDetails;

    public static ClassResource nrSecurityClassResource;
    public static ClassResource agentClassResource;

    private static String[] agentRelatedJarPatterns = new String[]{
            "newrelic-security-api", "newrelic-security-api-test-impl", "newrelic-api"
    };

    private static Set<URL> agentRelatedJars = new HashSet<>();

    static {
        try {
            instrumentation = getInstrumentationRef();
            weavePackageManager = new WeavePackageManager(new FailingWeavePackageListener(), SecurityInstrumentationTestRunner.instrumentation, 10, true, true);
            getSecurityClassResources();

            // Apply Security API adjusting transformers
            instrumentation.addTransformer(new SecurityApiClassTransformer(), true);

            // Added newrelic-security-api-test-impl jar to bootstrapsearch path since we now have bootstrap inst enabled.

            for (URL agentRelatedJar : agentRelatedJars) {
                JarFile jarFile = new JarFile(agentRelatedJar.getFile());
                instrumentation.appendToBootstrapClassLoaderSearch(jarFile);
                instrumentation.appendToSystemClassLoaderSearch(jarFile);

            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void getSecurityClassResources() throws Exception {
        List<ClassResource> classResources = ClassResource.fromClassLoader(TransformingTestUtils.getParentAsUrlClassLoader());
        for (ClassResource classResource : classResources) {
            String resourceName = classResource.resourceName;
            String className = resourceName.replace('/', '.').replace(".class", "");

            if (className.equals(NEW_RELIC_SECURITY_CLASS)) {
                if (StringUtils.contains(classResource.sourceURL.toString(), "newrelic-security-api-test-impl")) {
                    nrSecurityClassResource = classResource;
                }
            } else if (className.equals(SecurityInstrumentationTestRunner.AGENT_CLASS)) {
                if (StringUtils.contains(classResource.sourceURL.toString(), "newrelic-security-api-test-impl")) {
                    agentClassResource = classResource;
                }
            }
//
            if (StringUtils.containsAny(new File(classResource.sourceURL.getFile()).getName(), agentRelatedJarPatterns)) {
                agentRelatedJars.add(classResource.sourceURL);
            }
        }
    }

    public SecurityInstrumentationTestRunner(Class<?> classUnderTest) throws Exception {
        super(ImplementationLocator.loadWithInstrumentingClassLoader(classUnderTest, IntrospectorConfig.readConfig(classUnderTest)));
        configOverrides = IntrospectorConfig.readConfig(classUnderTest);
        instrumentation.addTransformer(new TestClassReTransformer(), true);
    }

    private static Instrumentation getInstrumentationRef() throws Exception {
        Class<?> instrumentationTestHelper = Class.forName("sun.reflect.com.nr.agent.security.instrumentation.InstrumentationTestHelper", false, null);
        Field instrumentationField = instrumentationTestHelper.getField("instrumentation");
        return (Instrumentation) instrumentationField.get(null);
    }

    @Override
    public void run(RunNotifier notifier) {
        super.run(notifier);
    }

    @Override
    protected void runChild(FrameworkMethod method, RunNotifier notifier) {
        super.runChild(method, notifier);
    }
}
