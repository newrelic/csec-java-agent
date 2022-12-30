/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.instrumentation;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.WeaveIntoAllMethods;
import com.newrelic.api.agent.weaver.WeaveWithAnnotation;

@WeaveWithAnnotation(annotationClasses = {
        "org.springframework.stereotype.Controller",
        "org.springframework.web.bind.annotation.RestController"},
        type = MatchType.ExactClass)
public class SpringController_Instrumentation {

    @WeaveWithAnnotation(annotationClasses = {
            "org.springframework.web.bind.annotation.RequestMapping",
            "org.springframework.web.bind.annotation.PatchMapping",
            "org.springframework.web.bind.annotation.PutMapping",
            "org.springframework.web.bind.annotation.GetMapping",
            "org.springframework.web.bind.annotation.PostMapping",
            "org.springframework.web.bind.annotation.DeleteMapping"})
    @WeaveIntoAllMethods
    @Trace
    private static void requestMapping() {
        preprocessSecurityHook();
    }

    private static void preprocessSecurityHook() {
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
