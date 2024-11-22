/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.api.agent.security;

/**
 * The New Relic Security API. Consumers of this API should add the newrelic-security-api.jar to their classpath. The static methods of
 * this class form the Security Agent's basic Java API. Use {@link NewRelicSecurity#getAgent} to obtain the root of a hierarchy of
 * objects offering additional capabilities.
 */
public final class NewRelicSecurity {

    private static SecurityAgent securityAgent = new NoOpAgent();

    /**
     * Returns the root of the New Relic Security Java Agent API object hierarchy.
     *
     * @return the root of the New Relic Security Java Agent API object hierarchy
     */
    public static SecurityAgent getAgent(){
        return securityAgent;
    }

    /**
     * Indicates whether the hook processing can be done in the instrumentation modules.
     * @return {@code true} iff security module init is completed and hook processing can be allowed.
     * {@code false} otherwise.
     */
    public static boolean isHookProcessingActive(){
        return false;
    }

    /**
     *  Marks the end of agent init. Hooks can now be processed.
     */
    public static void markAgentAsInitialised(){}

    public static String getSecurityMode(){
        return "IAST";
    }
}
