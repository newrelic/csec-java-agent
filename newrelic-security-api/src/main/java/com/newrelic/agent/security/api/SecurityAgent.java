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
 * The New Relic Security Java Agent's API.
 */
public interface SecurityAgent {

    boolean refreshState();

    boolean deactivateSecurity();

    void registerOperation(AbstractOperation operation, String executionId);

    boolean isSecurityActive();

    AgentPolicy getCurrentPolicy();

    /**
     * Returns the associated security related metadata from the current transaction in the context.
     * @return {@link SecurityAgent} object associated with the current transaction in the context or {@code null} otherwise.
     */
    SecurityMetaData getSecurityMetaData();

    /**
     * Indicates whether the hook processing can be done in the instrumentation modules.
     * @return {@code true} iff security module init is completed and hook processing can be allowed.
     * {@code false} otherwise.
     */
    boolean isHookProcessingActive();

}
