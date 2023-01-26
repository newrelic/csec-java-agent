/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.apache.commons.httpclient;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.constants.AgentConstants;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.agent.instrumentation.security.httpclient3.SecurityHelper;

import java.io.IOException;

@Weave(type = MatchType.ExactClass)
public abstract class HttpMethodBase implements HttpMethod {

    @NewField
    public boolean cascadedCall;

    public abstract void setRequestHeader(String headerName, String headerValue);

    public int execute(HttpState state, HttpConnection conn) throws HttpException, IOException {
        boolean currentCascadedCall = cascadedCall;
        // Preprocess Phase
        AbstractOperation operation = preprocessSecurityHook(currentCascadedCall, conn, SecurityHelper.METHOD_NAME_EXECUTE);

        int returnCode = -1;
        // Actual Call
        try {
            returnCode = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }
        registerExitOperation(operation);
        return returnCode;
    }

    private static void registerExitOperation(AbstractOperation operation) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }

    private AbstractOperation preprocessSecurityHook(boolean currentCascadedCall, HttpConnection conn, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
                    || currentCascadedCall
            ) {
                return null;
            }
            cascadedCall = true;

            // Generate required URL

            URI methodURI = null;
            String uri = null;
            String host = null;
            String scheme = null;
            int port = conn.getPort();
            try {
                methodURI = getURI();
                uri = methodURI.toString();
                if (methodURI == null) {
                    return null;
                }
                scheme = methodURI.getScheme();
                if (scheme == null) {
                    scheme = conn.getProtocol().getScheme();
                    host = conn.getHost();
                    String path = methodURI.getPath();
                    if (SecurityHelper.NULL_STRING.equals(path)) {
                        path = null;
                    }
                    uri = SecurityHelper.getURI(scheme, host, conn.getPort(), path);
                } else {
                    host = methodURI.getHost();
                    uri = SecurityHelper.getURI(methodURI.getScheme(), host, conn.getPort(), methodURI.getPath());
                }
            } catch (URIException ignored) {
                return null;
            }


            // TODO : Need to check if this is required anymore in NR case.
//            // Add Security app topology header
//            this.addRequestProperty("K2-API-CALLER", "");

            // Add Security IAST header
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                this.setRequestHeader(AgentConstants.K2_FUZZ_REQUEST_ID, iastHeader);
            }

            SSRFOperation operation = new SSRFOperation(uri,
                    this.getClass().getName(), methodName);
            try {
                NewRelicSecurity.getAgent().registerOperation(operation);
            } finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    this.setRequestHeader(AgentConstants.K2_TRACING_DATA, SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID()));
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
}
