/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.apache.solr.client.solrj.impl;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SolrDbOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.solr.client.solrj.ResponseParser;
import org.apache.solr.client.solrj.SolrRequest;
import org.apache.solr.client.solrj.SolrServerException;
import org.apache.solr.client.solrj.request.UpdateRequest;
import org.apache.solr.common.SolrInputDocument;
import org.apache.solr.common.params.SolrParams;
import org.apache.solr.common.util.NamedList;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.solr.client.solrj.impl.HttpSolrClient")
public abstract class HttpSolrClient_Instrumentation {


    public abstract String getBaseURL();

    protected HttpSolrClient_Instrumentation(Builder builder) {
        //TODO report external URL
    }

    public NamedList<Object> request(@SuppressWarnings({"rawtypes"})final SolrRequest request, final ResponseParser processor, String collection)
            throws SolrServerException, IOException {
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.SOLR_DB_REQUEST, "HTTP_SOLR_REQUEST-", request.hashCode());
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSolrRequest(request, "REQUEST");
        }
        NamedList<Object> result;
        try {
            result = Weaver.callOriginal();
        } finally {
            if(isLockAcquired) {
                GenericHelper.releaseLock("HTTP_SOLR_REQUEST-", request.hashCode());
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return result;
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExitEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, "HTTP_SOLR_SERVER_9.0.0", e.getMessage()), e, this.getClass().getName());
        }
    }

    private AbstractOperation preprocessSolrRequest(@SuppressWarnings({"rawtypes"})SolrRequest request, String methodName) {
        try {
            String collection = new URL(getBaseURL()).getPath();
            collection = collection.startsWith("/") ? collection.substring(1) : collection;
            String method = request.getMethod().toString();
            String path = request.getPath();
            SolrParams solrParams = request.getParams();
            Map<String, String> params = Collections.emptyMap();
            if(solrParams != null){
                params = SolrParams.toMap(solrParams.toNamedList());
            }
            List<SolrInputDocument> documents = Collections.emptyList();
            if(request instanceof UpdateRequest) {
                documents = ((UpdateRequest) request).getDocuments();
            }
            SolrDbOperation solrDbOperation = new SolrDbOperation(this.getClass().getName(), methodName);
            solrDbOperation.setCollection(collection);
            solrDbOperation.setParams(params);
            solrDbOperation.setDocuments(documents);
            solrDbOperation.setConnectionURL(getBaseURL());
            solrDbOperation.setMethod(method);
            solrDbOperation.setPath(path);
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format("Solr request %s, %s, %s, %s, %s", collection, method, path, params, documents), this.getClass().getName());
            NewRelicSecurity.getAgent().registerOperation(solrDbOperation);
            return solrDbOperation;
        } catch (MalformedURLException e){
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format("Instrumentation library: %s , error while extracting collection from baseUrl : %s, %s", "HTTP_SOLR_SERVER_9.0.0", getBaseURL(), e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format("Instrumentation library: %s , error while extracting collection from baseUrl : %s, %s", "HTTP_SOLR_SERVER_9.0.0", getBaseURL(), e.getMessage()), e, this.getClass().getName());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, "HTTP_SOLR_SERVER_9.0.0", e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, "HTTP_SOLR_SERVER_9.0.0", e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, "HTTP_SOLR_SERVER_9.0.0", e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

    @Weave(type = MatchType.ExactClass, originalName = "org.apache.solr.client.solrj.impl.HttpSolrClient$Builder")
    public static class Builder extends SolrClientBuilder<Builder> {
        protected String baseSolrUrl;

        @Override
        public Builder getThis() {
            return this;
        }
    }

}
