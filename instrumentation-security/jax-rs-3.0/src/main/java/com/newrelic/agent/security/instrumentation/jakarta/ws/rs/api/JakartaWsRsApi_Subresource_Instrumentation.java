/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.jakarta.ws.rs.api;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.WeaveIntoAllMethods;
import com.newrelic.api.agent.weaver.WeaveWithAnnotation;

/**
 * This instrumentation class is different from {@link JakartaWsRsApi_Instrumentation} because it does not look at class
 * annotations for matching purposes.
 * <p>
 * We capture the @Path method annotation if it's there but don't match on it because there can't be just an @Path
 * annotation on a method if it's not a subresource.
 * <p>
 * Case 1: Class annotation = @Path, method annotation = @Path, @GET
 * JavaxWsRsApi_Instrumentation will grab both path annotations and add them to the transaction name.
 * <p>
 * Case 2: Class annotation = @Path, method annotation = @GET, subresource method annotation = @Path
 * JavaxWsRsApi_Instrumentation annotation will grab the class path and JavaxWsRsApi_SubResource_Instrumentation will grab the subresource path.
 * <p>
 * Case 3: Class annotation = @Path, method annotation = @Path
 * This can't happen.
 */
public class JakartaWsRsApi_Subresource_Instrumentation {

    @WeaveWithAnnotation(annotationClasses = {"jakarta.ws.rs.PUT", "jakarta.ws.rs.POST", "jakarta.ws.rs.GET",
            "jakarta.ws.rs.DELETE", "jakarta.ws.rs.HEAD", "jakarta.ws.rs.OPTIONS", "jakarta.ws.rs.Path",
            "jakarta.ws.rs.PATCH"})
    @WeaveIntoAllMethods
    public static void preprocessSecurityHook() {
        ServletHelper.registerUserLevelCode("jax-rs");
        ServletHelper.setFoundAnnotatedUserLevelServiceMethod(true);
    }
}
