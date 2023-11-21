/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.api.agent.security;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;

import java.lang.instrument.Instrumentation;
import java.net.URL;

/**
 * The New Relic Security Java Agent's API.
 */
public interface SecurityAgent {

    boolean refreshState(URL agentJarURL, Instrumentation instrumentation);

    boolean deactivateSecurity();

    void registerOperation(AbstractOperation operation);

    void registerExitEvent(AbstractOperation operation);

    boolean isSecurityActive();

    AgentPolicy getCurrentPolicy();

    /**
     * Returns the associated security related metadata from the current transaction in the context.
     *
     * @return {@link SecurityAgent} object associated with the current transaction in the context or {@code null} otherwise.
     */
    SecurityMetaData getSecurityMetaData();

    String getAgentUUID();

    String getAgentTempDir();

    Instrumentation getInstrumentation();

    boolean isLowPriorityInstrumentationEnabled();

    void setServerInfo(String key, String value);
}
