/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.dynamodb_1_11_459;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.Request;
import com.amazonaws.services.dynamodbv2.model.BatchGetItemRequest;
import com.amazonaws.services.dynamodbv2.model.BatchWriteItemRequest;
import com.amazonaws.services.dynamodbv2.model.DeleteItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.KeysAndAttributes;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.TransactGetItem;
import com.amazonaws.services.dynamodbv2.model.TransactGetItemsRequest;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItem;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsRequest;
import com.amazonaws.services.dynamodbv2.model.UpdateItemRequest;
import com.amazonaws.services.dynamodbv2.model.WriteRequest;
import com.newrelic.api.agent.DatastoreParameters;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.helper.DynamoDBRequest;
import com.newrelic.api.agent.security.schema.operation.DynamoDBOperation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This uses {@link DatastoreParameters} to create external metrics for all DynamoDB calls in
 * {@link com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient} and {@link com.amazonaws.services.dynamodbv2.AmazonDynamoDBAsyncClient}.
 */
public abstract class DynamoDBUtil {
    private static final String NR_SEC_CUSTOM_ATTRIB_NAME = "NR_SEC_CUSTOM_ATTRIB_NAME";
    private static final String OP_READ = "read";
    private static final String OP_CREATE = "create";
    private static final String OP_WRITE = "write";
    private static final String OP_UPDATE = "update";
    private static final String OP_DELETE = "delete";

    public static <Y> AbstractOperation processDynamoDBRequest(Request<Y> yRequest, String klassName) {
        DynamoDBOperation operation = null;
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                List<DynamoDBRequest> requests = new ArrayList();
                AmazonWebServiceRequest request = yRequest.getOriginalRequest();

                operation = checkAndGenerateOperation(request, requests, klassName);

                if (operation!=null) {
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

    // collect data in generic form from nested data or from list of data else add original
    private static void addToList(List<DynamoDBRequest> list, AmazonWebServiceRequest value, String command) {
        try {
            if(value!=null) {
                if (value instanceof TransactGetItemsRequest){
                    TransactGetItemsRequest request = (TransactGetItemsRequest) value;
                    List<TransactGetItem> transactItems = request.getTransactItems();
                    for (int i=0; i< transactItems.size(); i++) {
                        if (transactItems.get(i).getGet() != null) {
                            list.add(new DynamoDBRequest(transactItems.get(i).getGet(), OP_READ));
                        }
                    }
                } else if (value instanceof TransactWriteItemsRequest){
                    TransactWriteItemsRequest request = (TransactWriteItemsRequest) value;
                    List<TransactWriteItem> transactItems = request.getTransactItems();
                    for (int i=0; i< transactItems.size(); i++) {
                        if (transactItems.get(i).getConditionCheck() != null) {
                            list.add(new DynamoDBRequest(transactItems.get(i).getConditionCheck(), OP_READ));
                        }
                        if (transactItems.get(i).getPut() != null) {
                            list.add(new DynamoDBRequest(transactItems.get(i).getPut(), OP_WRITE));
                        }
                        if (transactItems.get(i).getUpdate() != null) {
                            list.add(new DynamoDBRequest(transactItems.get(i).getUpdate(), OP_UPDATE));
                        }
                        if (transactItems.get(i).getDelete() != null) {
                            list.add(new DynamoDBRequest(transactItems.get(i).getDelete(), OP_DELETE));
                        }
                    }
                } else if (value instanceof BatchGetItemRequest){
                    BatchGetItemRequest request = (BatchGetItemRequest) value;
                    for (Map.Entry<String, KeysAndAttributes> entry : request.getRequestItems().entrySet())
                        if (entry.getValue() != null)
                            list.add(new DynamoDBRequest(entry.getValue(), OP_READ));
                } else if (value instanceof BatchWriteItemRequest){
                    BatchWriteItemRequest request = (BatchWriteItemRequest) value;
                    for (Map.Entry<String, List<WriteRequest>> entry : request.getRequestItems().entrySet())
                        if (entry.getValue() != null)
                            for(WriteRequest item : entry.getValue()) {
                                if (item.getPutRequest() != null) {
                                    list.add(new DynamoDBRequest(item.getPutRequest(), OP_WRITE));
                                }
                                if (item.getDeleteRequest() != null) {
                                    list.add(new DynamoDBRequest(item.getDeleteRequest(), OP_DELETE));
                                }
                            }
                } else {
                    list.add(new DynamoDBRequest(value, command));
                }
            }
        } catch (NullPointerException ignored){
        }
    }

    /**
     * This method is introduced to eliminate the unnecessary event being generated for CSEC agent
     */
    private static DynamoDBOperation checkAndGenerateOperation(AmazonWebServiceRequest value, List<DynamoDBRequest> requests, String klassName) {
        DynamoDBOperation operation = null;
        try {
            if (value instanceof BatchGetItemRequest) {
                BatchGetItemRequest request = (BatchGetItemRequest) value;
                boolean send = false;
                Map<String, KeysAndAttributes> requestItems = request.getRequestItems();
                for (Map.Entry<String, KeysAndAttributes> entry : requestItems.entrySet()) {
                    KeysAndAttributes value1 = entry.getValue();
                    if (value1 != null)
                        if (value1.getProjectionExpression()!=null) {
                            send = true;
                            break;
                        }
                }
                if (!send)
                    return null;
                addToList(requests, value, OP_READ);
                operation = new DynamoDBOperation(requests, klassName, "executeBatchGetItem", DynamoDBOperation.Category.AWSAPI);
            }
            else if (value instanceof BatchWriteItemRequest) {
                addToList(requests, value, OP_READ);
                operation = new DynamoDBOperation(requests, klassName, "executeBatchWriteItem", DynamoDBOperation.Category.AWSAPI);
            }
            else if (value instanceof DeleteItemRequest) {
                DeleteItemRequest request = (DeleteItemRequest) value;
                if (request.getConditionExpression() == null) {
                    return null;
                }
                addToList(requests, value, OP_DELETE);
                operation = new DynamoDBOperation(requests, klassName, "executeDeleteItem", DynamoDBOperation.Category.AWSAPI);
            }
            else if (value instanceof QueryRequest) {
                QueryRequest request = (QueryRequest) value;
                if (request.getFilterExpression() == null && request.getKeyConditionExpression() == null && request.getProjectionExpression() == null) {
                    return null;
                }
                addToList(requests, value, OP_READ);
                operation = new DynamoDBOperation(requests, klassName, "executeQuery", DynamoDBOperation.Category.AWSAPI);
            }
            else if (value instanceof GetItemRequest) {
                GetItemRequest request = (GetItemRequest) value;
                if (request.getProjectionExpression() == null) {
                    return null;
                }
                addToList(requests, value, OP_READ);
                operation = new DynamoDBOperation(requests, klassName, "executeGetItem", DynamoDBOperation.Category.AWSAPI);
            }
            else if (value instanceof PutItemRequest) {
                addToList(requests, value, OP_WRITE);
                operation = new DynamoDBOperation(requests, klassName, "executePutItem", DynamoDBOperation.Category.AWSAPI);
            }
            else if (value instanceof ScanRequest) {
                ScanRequest request = (ScanRequest) value;
                if (request.getProjectionExpression() == null && request.getFilterExpression() == null) {
                    return null;
                }
                addToList(requests, value, OP_READ);
                operation = new DynamoDBOperation(requests, klassName, "executeScan", DynamoDBOperation.Category.AWSAPI);
            }
            else if (value instanceof UpdateItemRequest) {
                addToList(requests, value, OP_UPDATE);
                operation = new DynamoDBOperation(requests, klassName, "executeUpdateItem", DynamoDBOperation.Category.AWSAPI);
            }
            else if (value instanceof TransactGetItemsRequest) {
                TransactGetItemsRequest request = (TransactGetItemsRequest) value;
                if (request.getTransactItems() == null && request.getTransactItems().size() == 0) {
                    return null;
                }
                int i;
                for (i = 0; i < request.getTransactItems().size(); i++) {
                    if (request.getTransactItems().get(i).getGet().getProjectionExpression() != null) {
                        break;
                    }
                    if (i + 1 == request.getTransactItems().size()) {
                        return null;
                    }
                }
                addToList(requests, value, OP_READ);
                operation = new DynamoDBOperation(requests, klassName, "transactGetItemsRequest", DynamoDBOperation.Category.AWSAPI);
            }
            else if (value instanceof TransactWriteItemsRequest) {
                addToList(requests, value, OP_WRITE);
                operation = new DynamoDBOperation(requests, klassName, "transactWriteItemsRequest", DynamoDBOperation.Category.AWSAPI);
            }

        } catch (NullPointerException ignored) {
        }
        return operation;
    }

}
