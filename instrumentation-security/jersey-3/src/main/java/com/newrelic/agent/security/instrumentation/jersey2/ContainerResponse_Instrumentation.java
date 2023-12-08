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
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weaver;
import org.glassfish.jersey.message.internal.OutboundJaxrsResponse;

import com.newrelic.api.agent.weaver.Weave;
import org.glassfish.jersey.message.internal.OutboundMessageContext;
import org.glassfish.jersey.server.ContainerRequest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper.SERVLET_GET_IS_OPERATION_LOCK;

@Weave(type = MatchType.ExactClass, originalName = "org.glassfish.jersey.server.ContainerResponse")
public abstract class ContainerResponse_Instrumentation {
    private boolean closed = Weaver.callOriginal();
    ContainerResponse_Instrumentation(final ContainerRequest requestContext, final OutboundJaxrsResponse response) {
        if(response != null && response.getContext() != null && response.getContext().hasEntity()){
            Object responseObject = response.getContext().getEntity();
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseBody(new StringBuilder(String.valueOf(responseObject)));
        }
    }

    public abstract OutboundMessageContext getWrappedMessageContext();

    public void close() {
        boolean isLockAcquired = false;
        try {
            isLockAcquired = GenericHelper.acquireLockIfPossible(SERVLET_GET_IS_OPERATION_LOCK);
            if(isLockAcquired && !closed) {
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
