/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.instrumentation.jakarta.ws.rs.api;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.WeaveIntoAllMethods;
import com.newrelic.api.agent.weaver.WeaveWithAnnotation;

@WeaveWithAnnotation(annotationClasses = {"jakarta.ws.rs.Path"}, type = MatchType.Interface)
public class JakartaWsRsApi_Instrumentation {

    @WeaveWithAnnotation(annotationClasses = {"jakarta.ws.rs.PUT", "jakarta.ws.rs.POST", "jakarta.ws.rs.GET",
            "jakarta.ws.rs.DELETE", "jakarta.ws.rs.HEAD", "jakarta.ws.rs.OPTIONS", "jakarta.ws.rs.PATCH"})
    @WeaveIntoAllMethods
    public static void preprocessSecurityHook() {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!securityMetaData.getMetaData().isUserLevelServiceMethodEncountered()) {
                securityMetaData.getMetaData().setUserLevelServiceMethodEncountered(true);
                securityMetaData.getMetaData().setServiceTrace(Thread.currentThread().getStackTrace());
            }
        } catch (Throwable ignored) {
        }
    }
}
