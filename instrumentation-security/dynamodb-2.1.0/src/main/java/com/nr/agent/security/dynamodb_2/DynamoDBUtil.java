/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.dynamodb_2;

import com.newrelic.api.agent.DatastoreParameters;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.helper.DynamoDBRequest;
import com.newrelic.api.agent.security.schema.operation.DynamoDBOperation;
import software.amazon.awssdk.core.SdkRequest;
import software.amazon.awssdk.core.SdkResponse;
import software.amazon.awssdk.core.client.handler.ClientExecutionParams;
import software.amazon.awssdk.core.runtime.transform.Marshaller;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteTransactionRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * This uses {@link DatastoreParameters} to create external metrics for all DynamoDB calls in
 * {@link software.amazon.awssdk.core.client.handler.SyncClientHandler} and {@link software.amazon.awssdk.core.client.handler.AsyncClientHandler}.
 */
public abstract class DynamoDBUtil {
    private static final String NR_SEC_CUSTOM_ATTRIB_NAME = "NR_SEC_CUSTOM_ATTRIB_NAME";
    private static final String OP_READ = "read";
    private static final String OP_CREATE = "create";
    private static final String OP_WRITE = "write";
    private static final String OP_UPDATE = "update";
    private static final String OP_DELETE = "delete";
    // TODO: used for setting uo the command type of PartiQL request that will be discussed later and updated accordingly
    private static final String OP_READ_WRITE = "read_write";

    public static <InputT extends SdkRequest, OutputT extends SdkResponse> AbstractOperation processDynamoDBRequest(ClientExecutionParams<InputT, OutputT> yRequest, String klassName) {
            DynamoDBOperation operation = null;
            try {
                if (NewRelicSecurity.isHookProcessingActive() &&
                        !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                    InputT request = yRequest.getInput();
                    if (request instanceof BatchGetItemRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_READ);
                        operation = new DynamoDBOperation(requests, klassName, "executeBatchGetItem", DynamoDBOperation.Category.DQL);
                    } else if (request instanceof BatchWriteItemRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_WRITE);
                        operation = new DynamoDBOperation(requests, klassName, "executeBatchWriteItem", DynamoDBOperation.Category.DQL);
                    } else if (request instanceof DeleteItemRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_DELETE);
                        operation = new DynamoDBOperation(requests, klassName, "executeDeleteItem", DynamoDBOperation.Category.DQL);
                    } else if (request instanceof QueryRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_READ);
                        operation = new DynamoDBOperation(requests, klassName, "executeQuery", DynamoDBOperation.Category.DQL);
                    } else if (request instanceof GetItemRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_READ);
                        operation = new DynamoDBOperation(requests, klassName, "executeGetItem", DynamoDBOperation.Category.DQL);
                    } else if (request instanceof PutItemRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_WRITE);
                        operation = new DynamoDBOperation(requests, klassName, "executePutItem", DynamoDBOperation.Category.DQL);
                    } else if (request instanceof ScanRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_READ);
                        operation = new DynamoDBOperation(requests, klassName, "executeScan", DynamoDBOperation.Category.DQL);
                    } else if (request instanceof UpdateItemRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_UPDATE);
                        operation = new DynamoDBOperation(requests, klassName, "executeUpdateItem", DynamoDBOperation.Category.DQL);
                    } else if (request instanceof ExecuteStatementRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_READ_WRITE);
                        operation = new DynamoDBOperation(requests, klassName, "executeStatement", DynamoDBOperation.Category.PARTIQL);
                    } else if (request instanceof BatchExecuteStatementRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_READ_WRITE);
                        operation = new DynamoDBOperation(requests, klassName, "batchExecuteStatement", DynamoDBOperation.Category.PARTIQL);
                    } else if (request instanceof ExecuteTransactionRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_READ_WRITE);
                        operation = new DynamoDBOperation(requests, klassName, "executeTransaction", DynamoDBOperation.Category.PARTIQL);
                    } else if (request instanceof TransactGetItemsRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_READ);
                        operation = new DynamoDBOperation(requests, klassName, "transactGetItemsRequest", DynamoDBOperation.Category.DQL);
                    } else if (request instanceof TransactWriteItemsRequest) {
                        List<DynamoDBRequest> requests = getMarshalledRequest(yRequest.getMarshaller(), request, OP_WRITE);
                        operation = new DynamoDBOperation(requests, klassName, "transactWriteItemsRequest", DynamoDBOperation.Category.DQL);
                    }

                    if (operation != null){
                        NewRelicSecurity.getAgent().registerOperation(operation);
                    }
                }
            } catch (Throwable e) {
                e.printStackTrace();
                if (e instanceof NewRelicSecurityException) {
                    e.printStackTrace();
                }
            }
            return operation;
    }

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }

    public static void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
    }

    public static boolean acquireLockIfPossible(int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static <T> void addToMap(List<DynamoDBRequest> list, T value, String command) {
        try {
            if(value!=null)
                list.add(new DynamoDBRequest(value, command));
        } catch (NullPointerException ignored){
        }
    }

    private static String getRequestString(SdkHttpFullRequest obj) throws IOException {
        StringBuilder string = new StringBuilder();
        if (obj!=null) {
            Optional<ContentStreamProvider> optional = obj.contentStreamProvider();
            if (optional.isPresent()) {
                try (InputStream input = optional.get().newStream()) {
                    for (int ch; (ch = input.read()) != -1; ) {
                        string.append((char) ch);
                    }
                }
            }
        }
        return string.toString();
    }

    private static <InputT> List<DynamoDBRequest> getMarshalledRequest(Marshaller<InputT> marshaller,
            InputT request, String command) throws IOException {
        List<DynamoDBRequest> requests = new ArrayList<>();
        SdkHttpFullRequest obj = marshaller.marshall(request);
        String string = getRequestString(obj);
        addToMap(requests, string, command);
        return requests;
    }
}
