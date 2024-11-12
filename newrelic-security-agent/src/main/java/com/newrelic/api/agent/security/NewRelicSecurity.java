/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.api.agent.security;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.intcodeagent.iast.monitoring.IastMonitoring;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ThreadLocalLockHelper;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.apache.commons.lang3.StringUtils;

/**
 * The New Relic Security API Implementation. Use {@link NewRelicSecurity#getAgent} to obtain the root of a hierarchy of
 * objects offering additional capabilities.
 */
public final class NewRelicSecurity {

    /**
     * Returns the root of the New Relic Security Java Agent API object hierarchy.
     *
     * @return the root of the New Relic Security Java Agent API object hierarchy
     */
    public static SecurityAgent getAgent(){
        return Agent.getInstance();
    }


    /**
     * Indicates whether the hook processing can be done in the instrumentation modules.
     * @return {@code true} iff security module init is completed and hook processing can be allowed.
     * {@code false} otherwise.
     */
    public static boolean isHookProcessingActive(){
        return AgentConfig.getInstance().isNRSecurityEnabled() && Agent.getInstance().isSecurityActive() && !ThreadLocalLockHelper.isLockHeldByCurrentThread() && !isInternalThread()
                && NewRelic.getAgent().getTransaction() != null
                && NewRelic.getAgent().getTransaction().getSecurityMetaData() instanceof SecurityMetaData
                && IastMonitoring.shouldProcessInterception();
//                (Agent.getInstance().getSecurityMetaData() != null);
    }

    public static boolean isInternalThread(){
        return StringUtils.startsWithAny(Thread.currentThread().getName(),
                "NR-CSEC", "New Relic", "NewRelic", "Newrelic");
    }
}
