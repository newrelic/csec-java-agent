/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.instrumentation.security.jersey.client1;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientRequest;
import com.sun.jersey.api.client.ClientResponse;

import java.util.Collections;

@Weave(type = MatchType.Interface, originalName = "com.sun.jersey.api.client.ClientHandler")
public class ClientHandler_Instrumentation {

    public ClientResponse handle(ClientRequest request) throws ClientHandlerException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(request, request.getURI().toString(), SecurityHelper.METHOD_NAME_HANDLE);
        }
        ClientResponse response = null;
        // Actual Call
        try {
            response = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return response;
    }

    private AbstractOperation preprocessSecurityHook(ClientRequest request, String uri, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

            // TODO : Need to check if this is required anymore in NR case.
//            // Add Security app topology header
//            this.addRequestProperty("K2-API-CALLER", "");

            // Add Security IAST header
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                request.getHeaders().put(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, Collections.singletonList(iastHeader));
            }

            SSRFOperation operation = new SSRFOperation(uri, this.getClass().getName(), methodName);
            try {
                NewRelicSecurity.getAgent().registerOperation(operation);
            } finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    request.getHeaders().put(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, Collections.singletonList(SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID())));
                }
            }
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME, this.hashCode());
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }
    
}
