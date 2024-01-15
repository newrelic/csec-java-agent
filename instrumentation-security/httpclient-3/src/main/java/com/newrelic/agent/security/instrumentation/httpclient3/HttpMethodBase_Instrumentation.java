/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.httpclient3;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.commons.httpclient.*;

import java.io.IOException;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.commons.httpclient.HttpMethodBase")
public abstract class HttpMethodBase_Instrumentation {

    public abstract URI getURI() throws URIException;
    public abstract void setRequestHeader(String headerName, String headerValue);

    public int execute(HttpState state, HttpConnection conn) throws HttpException, IOException {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        // Preprocess Phase
        if (isLockAcquired) {
            operation = preprocessSecurityHook(conn, SecurityHelper.METHOD_NAME_EXECUTE);
        }
        int returnCode = -1;
        // Actual Call
        try {
            returnCode = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnCode;
    }

    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_3, ignored.getMessage()), ignored, HttpMethodBase_Instrumentation.class.getName());
        }
    }

    private AbstractOperation preprocessSecurityHook(HttpConnection conn, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
            ) {
                return null;
            }

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
            } catch (Exception e) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.URI_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_3, e.getMessage()), e, this.getClass().getName());
                return null;
            }


            // TODO : Need to check if this is required anymore in NR case.
//            // Add Security app topology header
//            this.addRequestProperty("K2-API-CALLER", "");

            // Add Security IAST header
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                this.setRequestHeader(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
            }

            String csecParentId = SecurityHelper.getParentId();
            if(csecParentId!= null && !csecParentId.isEmpty()){
                this.setRequestHeader(GenericHelper.CSEC_PARENT_ID, csecParentId);
            }

            SSRFOperation operation = new SSRFOperation(uri,
                    this.getClass().getName(), methodName);
            try {
                NewRelicSecurity.getAgent().registerOperation(operation);
            } catch (Exception e) {
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_3, e.getMessage()), e, this.getClass().getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_3, e.getMessage()), e, this.getClass().getName());
            }
            finally {
                if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    this.setRequestHeader(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID()));
                }
            }
            return operation;
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_3, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_3, e.getMessage()), e, this.getClass().getName());
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, SecurityHelper.HTTP_CLIENT_3, e.getMessage()), e, this.getClass().getName());
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
}
