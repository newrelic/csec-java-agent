/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.api.agent.security;

import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;

import java.lang.instrument.Instrumentation;
import java.net.URL;

/**
 * Provides NoOps for API objects to avoid returning <code>null</code>. Do not call these objects directly.
 */
class NoOpAgent implements SecurityAgent {
    private static final SecurityAgent INSTANCE = new NoOpAgent();
    public static final String EMPTY = "";

    public static SecurityAgent getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean refreshState(URL agentJarURL, Instrumentation instrumentation) {
        return true;
    }

    @Override
    public boolean deactivateSecurity() {
        return true;
    }

    @Override
    public void registerOperation(AbstractOperation operation) {
    }

    @Override
    public void registerExitEvent(AbstractOperation operation) {}

    @Override
    public boolean isSecurityActive() {
        return false;
    }

    @Override
    public AgentPolicy getCurrentPolicy() {
        return new AgentPolicy();
    }

    @Override
    public SecurityMetaData getSecurityMetaData() {
        return null;
    }

    @Override
    public String getAgentUUID() {
        return EMPTY;
    }

    @Override
    public String getAgentTempDir() {
        return EMPTY;
    }

    @Override
    public Instrumentation getInstrumentation() {
        return null;
    }

    @Override
    public boolean isLowPriorityInstrumentationEnabled() {
        return false;
    }

}
