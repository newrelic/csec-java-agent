/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.api.agent.security;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.ServerConnectionConfiguration;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.schema.policy.IastDetectionCategory;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.util.Map;

/**
 * The New Relic Security Java Agent's API.
 */
public interface SecurityAgent {

    IastDetectionCategory getIastDetectionCategory();

    boolean refreshState(URL agentJarURL, Instrumentation instrumentation);

    boolean deactivateSecurity();

    void registerOperation(AbstractOperation operation);

    void registerExitEvent(AbstractOperation operation);

    boolean isSecurityActive();

    AgentPolicy getCurrentPolicy();

    /**
     * Returns the associated security related metadata from the current transaction in the context.
     *
     * @return {@link SecurityAgent} object associated with the current transaction in the context or {@code null} otherwise.
     */
    SecurityMetaData getSecurityMetaData();

    String getAgentUUID();

    String getAgentTempDir();

    Instrumentation getInstrumentation();

    boolean isLowPriorityInstrumentationEnabled();

    void setServerInfo(String key, String value);

    String getServerInfo(String key);

    void setApplicationConnectionConfig(int port, String scheme);

    ServerConnectionConfiguration getApplicationConnectionConfig(int port);

    Map<Integer, ServerConnectionConfiguration> getApplicationConnectionConfig();

    void log(LogLevel logLevel, String event, Throwable throwableEvent, String logSourceClassName);

    void log(LogLevel logLevel, String event, String logSourceClassName);

    void reportIncident(LogLevel logLevel, String event, Throwable exception, String caller);

    void reportIASTScanFailure(SecurityMetaData securityMetaData, String apiId, Throwable exception,
                               String nrCsecFuzzRequestId, String controlCommandId, String failureMessage);

    void retransformUninstrumentedClass(Class<?> classToRetransform);

    String decryptAndVerify(String encryptedData, String hashVerifier);

    void reportApplicationRuntimeError(SecurityMetaData securityMetaData, Throwable exception);

    boolean recordExceptions(SecurityMetaData securityMetaData, Throwable exception);

    void reportURLMapping();

    boolean isSecurityEnabled();
}
