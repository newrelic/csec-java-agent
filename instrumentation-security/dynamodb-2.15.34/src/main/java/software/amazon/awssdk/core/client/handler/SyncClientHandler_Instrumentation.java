/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package software.amazon.awssdk.core.client.handler;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.dynamodb_215.DynamoDBUtil;
import software.amazon.awssdk.core.SdkRequest;
import software.amazon.awssdk.core.SdkResponse;
import software.amazon.awssdk.core.sync.ResponseTransformer;

@Weave(originalName = "software.amazon.awssdk.core.client.handler.SyncClientHandler", type = MatchType.Interface)
public class SyncClientHandler_Instrumentation {

    public <InputT extends SdkRequest, OutputT extends SdkResponse> OutputT execute(
            ClientExecutionParams<InputT, OutputT> executionParams) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = DynamoDBUtil.acquireLockIfPossible(this.hashCode());
        if (isLockAcquired) {
            noSQLOperation = DynamoDBUtil.processDynamoDBRequest(executionParams, this.getClass().getName());
        }
        OutputT returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
            ignored.printStackTrace();
        } finally {
            if (isLockAcquired) {
                DynamoDBUtil.releaseLock(this.hashCode());
            }
        }
        DynamoDBUtil.registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }

    public <InputT extends SdkRequest, OutputT extends SdkResponse, ReturnT> ReturnT execute(
            ClientExecutionParams<InputT, OutputT> executionParams,
            ResponseTransformer<OutputT, ReturnT> responseTransformer) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = DynamoDBUtil.acquireLockIfPossible(this.hashCode());
        if (isLockAcquired) {
            noSQLOperation = DynamoDBUtil.processDynamoDBRequest(executionParams, this.getClass().getName());
        }
        ReturnT returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
            ignored.printStackTrace();
        } finally {
            if (isLockAcquired) {
                DynamoDBUtil.releaseLock(this.hashCode());
            }
        }
        DynamoDBUtil.registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }
}
