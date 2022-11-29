/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.api;

import com.newrelic.agent.security.schema.AbstractOperation;
import com.newrelic.agent.security.schema.SecurityMetaData;
import com.newrelic.agent.security.schema.policy.AgentPolicy;

/**
 * Provides NoOps for API objects to avoid returning <code>null</code>. Do not call these objects directly.
 */
class NoOpAgent implements SecurityAgent {
    private static final SecurityAgent INSTANCE = new NoOpAgent();

    public static SecurityAgent getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean refreshState() {
        return true;
    }

    @Override
    public boolean deactivateSecurity() {
        return true;
    }

    @Override
    public void registerOperation(AbstractOperation operation, String executionId) {
    }

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
    public boolean isHookProcessingActive() {
        return false;
    }
}
