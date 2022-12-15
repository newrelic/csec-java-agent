/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.introspec;

import com.newrelic.agent.security.introspec.internal.ImplementationLocator;
import com.newrelic.agent.security.introspec.internal.IntrospectorConfig;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;

import java.util.Map;

public final class SecurityInstrumentationTestRunner extends BlockJUnit4ClassRunner {

    private static SecurityIntrospector INTROSPECTOR = null;
    private final Map<String, Object> configOverrides;

    public SecurityInstrumentationTestRunner(Class<?> classUnderTest) throws Exception {
        super(ImplementationLocator.loadWithInstrumentingClassLoader(classUnderTest, IntrospectorConfig.readConfig(classUnderTest)));
        configOverrides = IntrospectorConfig.readConfig(classUnderTest);
    }

    @Override
    public void run(RunNotifier notifier) {
        INTROSPECTOR = ImplementationLocator.createIntrospector(configOverrides);
        super.run(notifier);
        INTROSPECTOR = null;
    }

    @Override
    protected void runChild(FrameworkMethod method, RunNotifier notifier) {
        INTROSPECTOR.clear();
        super.runChild(method, notifier);
    }

    public static SecurityIntrospector getIntrospector() {
        return INTROSPECTOR;
    }
}
