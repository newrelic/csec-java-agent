/*
 *
 *  * Copyright 2023 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.httpclient50;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.nio.AsyncEntityProducer;

import static com.newrelic.agent.security.instrumentation.httpclient50.SecurityHelper.APACHE5_ASYNC_REQUEST_PRODUCER;

@Weave(type=MatchType.BaseClass, originalName = "org.apache.hc.core5.http.nio.support.BasicRequestProducer")
public class BasicRequestProducer_Instrumentation {

    public BasicRequestProducer_Instrumentation(final HttpRequest request, final AsyncEntityProducer dataProducer) {
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(APACHE5_ASYNC_REQUEST_PRODUCER+this.hashCode(), request);
    }
}
