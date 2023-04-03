/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.instrumentation.security.urlconnection;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

@Weave(type = MatchType.BaseClass, originalName = "java.net.URLConnection")
public abstract class URLConnection_Instrumentation {

    @NewField
    public boolean cascadedCall;

    protected URL url;

    protected URLConnection_Instrumentation(URL url) {
        this.url = url;
    }

    public abstract void setRequestProperty(String key, String value);

    public abstract URL getURL();

    public void connect() throws IOException {
        String url = null;
        AbstractOperation operation = null;
        URL getURL = getURL();
        if(getURL != null) {
            url = getURL.toString();
            boolean currentCascadedCall = cascadedCall;
            // Preprocess Phase
            operation = preprocessSecurityHook(currentCascadedCall, url, getURL.getProtocol(), Helper.METHOD_NAME_CONNECT);
        }
        // Actual Call
        try {
            Weaver.callOriginal();
        } finally {
            /* Not calling `cascadedCall = currentCascadedCall;` is intentional.
            * This saves from generating additional getInputStream events while processing a call.
            * */
        }
        registerExitOperation(operation);
    }

    public synchronized OutputStream getOutputStream() throws IOException {
        String url = null;
        AbstractOperation operation = null;
        URL getURL = getURL();
        if(getURL != null) {
            url = getURL.toString();
            boolean currentCascadedCall = cascadedCall;
            // Preprocess Phase
            operation = preprocessSecurityHook(currentCascadedCall, url, getURL.getProtocol(), Helper.METHOD_NAME_GET_OUTPUT_STREAM);
        }
        // Actual Call
        OutputStream returnStream = null;
        try {
            returnStream = Weaver.callOriginal();
        } finally {
            /* Not calling `cascadedCall = currentCascadedCall;` is intentional.
             * This saves from generating additional getInputStream events while processing a call.
             * */
        }
        registerExitOperation(operation);
        return returnStream;
    }

    public synchronized InputStream getInputStream() throws IOException {
        String url = null;
        AbstractOperation operation = null;
        URL getURL = getURL();
        if(getURL != null) {
            url = getURL.toString();
            boolean currentCascadedCall = cascadedCall;
            // Preprocess Phase
            operation = preprocessSecurityHook(currentCascadedCall, url, getURL.getProtocol(), Helper.METHOD_NAME_GET_INPUT_STREAM);
        }
        // Actual Call
        InputStream returnStream = null;
        try {
            returnStream = Weaver.callOriginal();
        } finally {
            /* Not calling `cascadedCall = currentCascadedCall;` is intentional.
             * This saves from generating additional getInputStream events while processing a call on same object.
             * */
        }
        registerExitOperation(operation);
        return returnStream;
    }

    private static void registerExitOperation(AbstractOperation operation) {
        try {
            if (operation == null || operation.isEmpty() || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
    }

    private AbstractOperation preprocessSecurityHook(boolean currentCascadedCall, String callArgs, String protocol, String methodName) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!NewRelicSecurity.isHookProcessingActive() || securityMetaData.getRequest().isEmpty()
                    || callArgs == null || callArgs.trim().isEmpty() || currentCascadedCall
            ) {
                return null;
            }
            cascadedCall = true;
            // Generate FileOperation for applicable cases.
            if(protocol == null ||
                    protocol.trim().isEmpty() ||
                    protocol.equalsIgnoreCase(Helper.FILE) ||
                    protocol.equalsIgnoreCase(Helper.JAR) ||
                    protocol.equalsIgnoreCase(Helper.WAR)) {
                return null;
            }

            // TODO : Need to check if this is required anymore in NR case.
//            // Add Security app topology header
//            this.addRequestProperty("K2-API-CALLER", "");

            // Add Security IAST header
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if(iastHeader != null && !iastHeader.trim().isEmpty()) {
                this.setRequestProperty(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
            }

            SSRFOperation operation = new SSRFOperation(callArgs,
                    this.getClass().getName(), methodName);
            try {
                NewRelicSecurity.getAgent().registerOperation(operation);
            } finally {
                if(operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                        operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
                    // Add Security distributed tracing header
                    this.setRequestProperty(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, SSRFUtils.generateTracingHeaderValue(securityMetaData.getTracingHeaderValue(), operation.getApiID(), operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID()));
                }
            }
            return operation;
        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }
}
