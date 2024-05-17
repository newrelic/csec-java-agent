/*
 *
 *  * Copyright 2023 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.httpclient50;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.nio.AsyncEntityProducer;

import static com.newrelic.agent.security.instrumentation.httpclient50.SecurityHelper.APACHE5_ASYNC_REQUEST_PRODUCER;

@Weave(type=MatchType.BaseClass, originalName = "org.apache.hc.core5.http.nio.support.BasicRequestProducer")
public class BasicRequestProducer_Instrumentation {

    public BasicRequestProducer_Instrumentation(final HttpRequest request, final AsyncEntityProducer dataProducer) {
        try {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(APACHE5_ASYNC_REQUEST_PRODUCER+this.hashCode(), request);
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, SecurityHelper.HTTPCLIENT_5_0, e.getMessage()), e, this.getClass().getName());
        }
    }
}
