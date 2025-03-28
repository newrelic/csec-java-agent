/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.javax.ws.rs.api;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.WeaveIntoAllMethods;
import com.newrelic.api.agent.weaver.WeaveWithAnnotation;

@WeaveWithAnnotation(annotationClasses = {"javax.ws.rs.Path"}, type = MatchType.Interface)
public class JavaxWsRsApi_Instrumentation {

    @WeaveWithAnnotation(annotationClasses = {"javax.ws.rs.PUT", "javax.ws.rs.POST", "javax.ws.rs.GET",
            "javax.ws.rs.DELETE", "javax.ws.rs.HEAD", "javax.ws.rs.OPTIONS", "javax.ws.rs.PATCH"})
    @WeaveIntoAllMethods
    public static void preprocessSecurityHook() {
        ServletHelper.registerUserLevelCode("jax-rs");
        ServletHelper.setFoundAnnotatedUserLevelServiceMethod(true);
    }
}
