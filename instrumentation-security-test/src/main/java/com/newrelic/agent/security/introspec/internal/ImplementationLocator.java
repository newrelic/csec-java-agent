/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.Agent;
import com.newrelic.agent.bridge.AgentBridge;
import com.newrelic.agent.config.AgentConfig;
import com.newrelic.agent.instrumentation.InstrumentationImpl;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.service.ServiceFactory;
import com.newrelic.weave.weavepackage.ErrorTrapHandler;
import com.newrelic.weave.weavepackage.WeavePostprocessor;
import com.newrelic.weave.weavepackage.WeavePreprocessor;
import org.junit.runners.model.InitializationError;

import java.util.Map;

public class ImplementationLocator {

    public static Class<?> loadWithWeavingClassLoader(Class<?> classUnderTest) throws InitializationError {
        return TransformingTestUtils.applyClassLoader(classUnderTest, new WeavingClassLoader(
                TransformingTestUtils.getParentAsUrlClassLoader(),
                WeaveIncludes.readWeaveTestConfigIncludePrefixes(classUnderTest),
                ErrorTrapHandler.NO_ERROR_TRAP_HANDLER, WeavePreprocessor.NO_PREPROCESSOR,
                WeavePostprocessor.NO_POSTPROCESSOR));
    }

    public static Class<?> loadWithInstrumentingClassLoader(Class<?> classUnderTest, Map<String, Object> configOverrides) throws Exception {
        IntrospectorServiceManager manager = IntrospectorServiceManager.createAndInitialize(configOverrides);
        try {
            manager.start();
        } catch (Exception e) {
            // app will not work correctly
        }

        // initialize services / APIs
        com.newrelic.api.agent.NewRelicApiImplementation.initialize();
        com.newrelic.agent.PrivateApiImpl.initialize(Agent.LOG);
        AgentBridge.instrumentation = new InstrumentationImpl(Agent.LOG);

        AgentConfig agentConfig = ServiceFactory.getConfigService().getDefaultAgentConfig();
        SecurityInstrumentationTestRunner.instrumentingClassloader = new InstrumentingClassLoader(
                TransformingTestUtils.getParentAsUrlClassLoader(), WeaveIncludes.readWeaveTestConfigIncludePrefixes(
                classUnderTest), agentConfig);
        return TransformingTestUtils.applyClassLoader(classUnderTest, SecurityInstrumentationTestRunner.instrumentingClassloader);
    }
}
