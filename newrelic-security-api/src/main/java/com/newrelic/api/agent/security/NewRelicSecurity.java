/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.api.agent.security;

import java.lang.reflect.Method;

/**
 * The New Relic Security API. Consumers of this API should add the newrelic-security-api.jar to their classpath. The static methods of
 * this class form the Security Agent's basic Java API. Use {@link NewRelicSecurity#getAgent} to obtain the root of a hierarchy of
 * objects offering additional capabilities.
 */
public final class NewRelicSecurity {

    private static boolean initDone = false;

    private static SecurityAgent securityAgent = new NoOpAgent();

    /**
     * Finds and initialises New Relic Security Agent if present on the call path or places
     * NoOp impl otherwise.
     * Only the New Relic APM agent present in the runtime should call this method.
     * This is not meant to be called outside APM agent.
     */
    public static void initialise(SecurityAgent securityAgentObj) {
        try {
            if (securityAgentObj != null) {
                securityAgent = securityAgentObj;
                initDone = true;
            }
        } catch (Throwable ignored) {
            // TODO: Potential to add NewRelic Agent API to get logger to log this error in some cases.
        }
    }

    /**
     * Returns the root of the New Relic Security Java Agent API object hierarchy.
     *
     * @return the root of the New Relic Security Java Agent API object hierarchy
     */
    public static SecurityAgent getAgent(){
        return securityAgent;
    }

    /**
     * Get New Relic Security init status.
     * @return {@code true} iff {@link #initialise(SecurityAgent securityAgentObj)} has been already called and succeeded. {@code false} otherwise
     */
    public static boolean isInitialised() {
        return initDone;
    }

}
