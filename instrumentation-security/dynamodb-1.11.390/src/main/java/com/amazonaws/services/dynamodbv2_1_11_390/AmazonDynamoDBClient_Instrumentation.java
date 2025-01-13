/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.amazonaws.services.dynamodbv2_1_11_390;

import com.amazonaws.AmazonWebServiceClient;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.AmazonWebServiceResponse;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.Request;
import com.amazonaws.Response;
import com.amazonaws.http.ExecutionContext;
import com.amazonaws.http.HttpResponseHandler;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.dynamodb_1_11_390.DynamoDBUtil;

import java.net.URI;

/**
 * This provides external instrumentation for Amazon's DynamoDB Java API 1.9.0+. Metrics are all generated in
 * {@link DynamoDBUtil} - all that's different from one method to another is the method name.
 */
@Weave(originalName = "com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient")
public abstract class AmazonDynamoDBClient_Instrumentation extends AmazonWebServiceClient {

    public AmazonDynamoDBClient_Instrumentation(ClientConfiguration clientConfiguration) {
        super(clientConfiguration);
    }

    private <X, Y extends AmazonWebServiceRequest> Response<X> doInvoke(Request<Y> request, HttpResponseHandler<AmazonWebServiceResponse<X>> responseHandler,
            ExecutionContext executionContext, URI discoveredEndpoint) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = DynamoDBUtil.acquireLockIfPossible(VulnerabilityCaseType.NOSQL_DB_COMMAND, request.hashCode());
        if (isLockAcquired) {
            noSQLOperation = DynamoDBUtil.processDynamoDBRequest(request, this.getClass().getName());
        }
        Response<X> returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                DynamoDBUtil.releaseLock(request.hashCode());
            }
        }
        DynamoDBUtil.registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }
}
