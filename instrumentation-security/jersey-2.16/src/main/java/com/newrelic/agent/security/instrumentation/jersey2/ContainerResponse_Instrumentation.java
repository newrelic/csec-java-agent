/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.jersey2;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weaver;
import org.glassfish.jersey.message.internal.OutboundJaxrsResponse;

import com.newrelic.api.agent.weaver.Weave;
import org.glassfish.jersey.message.internal.OutboundMessageContext;
import org.glassfish.jersey.server.ContainerRequest;


import static com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper.SERVLET_GET_IS_OPERATION_LOCK;

@Weave(type = MatchType.ExactClass, originalName = "org.glassfish.jersey.server.ContainerResponse")
public abstract class ContainerResponse_Instrumentation {

    ContainerResponse_Instrumentation(final ContainerRequest requestContext, final OutboundJaxrsResponse response) {
        if (NewRelicSecurity.getAgent().getSecurityMetaData() != null) {
            if (response != null) {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setStatusCode(response.getStatus());
            }

        if(GenericHelper.isLockAcquired(HttpRequestHelper.getNrSecCustomAttribForPostProcessing()) && response != null && response.getContext() != null && response.getContext().hasEntity()){
            Object responseObject = response.getContext().getEntity();
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setBody(new StringBuilder(String.valueOf(responseObject)));
        }
    }

    public abstract OutboundMessageContext getWrappedMessageContext();

    public void close() {
        boolean isLockAcquired = false;
        try {
            isLockAcquired = GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.REFLECTED_XSS, SERVLET_GET_IS_OPERATION_LOCK);
            if(isLockAcquired && GenericHelper.isLockAcquired(HttpRequestHelper.getNrSecCustomAttribForPostProcessing())) {
                HttpRequestHelper.postProcessSecurityHook(this.getClass().getName(), getWrappedMessageContext());
            }
            Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                GenericHelper.releaseLock(SERVLET_GET_IS_OPERATION_LOCK);
            }
        }
    }
}
