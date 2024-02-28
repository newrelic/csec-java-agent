/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.dynamodb_1_11_459;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.Request;
import com.amazonaws.services.dynamodbv2.model.BatchGetItemRequest;
import com.amazonaws.services.dynamodbv2.model.BatchWriteItemRequest;
import com.amazonaws.services.dynamodbv2.model.ConditionCheck;
import com.amazonaws.services.dynamodbv2.model.Delete;
import com.amazonaws.services.dynamodbv2.model.DeleteItemRequest;
import com.amazonaws.services.dynamodbv2.model.DeleteRequest;
import com.amazonaws.services.dynamodbv2.model.Get;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.KeysAndAttributes;
import com.amazonaws.services.dynamodbv2.model.Put;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.PutRequest;
import com.amazonaws.services.dynamodbv2.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.TransactGetItem;
import com.amazonaws.services.dynamodbv2.model.TransactGetItemsRequest;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItem;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsRequest;
import com.amazonaws.services.dynamodbv2.model.Update;
import com.amazonaws.services.dynamodbv2.model.UpdateItemRequest;
import com.amazonaws.services.dynamodbv2.model.WriteRequest;
import com.newrelic.api.agent.DatastoreParameters;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.helper.DynamoDBRequest;
import com.newrelic.api.agent.security.schema.operation.DynamoDBOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    public static final String DYNAMODB_1_11_459 = "DYNAMODB-1.11.459";

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
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, DYNAMODB_1_11_459, e.getMessage()), e, DynamoDBUtil.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, DYNAMODB_1_11_459, e.getMessage()), e, DynamoDBUtil.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, DYNAMODB_1_11_459, e.getMessage()), e, DynamoDBUtil.class.getName());
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
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, DYNAMODB_1_11_459, ignored.getMessage()), ignored, DynamoDBUtil.class.getName());
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

    /**
     * This method is introduced to eliminate the unnecessary event being generated for CSEC agent
     */
    private static DynamoDBOperation checkAndGenerateOperation(AmazonWebServiceRequest value, List<DynamoDBRequest> requests, String klassName) {
        DynamoDBOperation operation = null;
        try {
            if (value instanceof BatchGetItemRequest) {
                BatchGetItemRequest request = (BatchGetItemRequest) value;
                Map<String, KeysAndAttributes> requestItems = request.getRequestItems();
                boolean generate = false;
                int i = 0;
                Set<Map.Entry<String, KeysAndAttributes>> entries = requestItems.entrySet();
                for (Map.Entry<String, KeysAndAttributes> entry : entries)
                    if (entry.getValue() != null) {
                        KeysAndAttributes value1 = entry.getValue();
                        if (value1.getProjectionExpression() != null) {
                            generate = true;
                        }
                        if (i + 1 == entries.size() && !generate) {
                            return null;
                        }
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setKey(value1.getKeys());
                        query.setProjectionExpression(value1.getProjectionExpression());
                        query.setExpressionAttributeNames(value1.getExpressionAttributeNames());
                        query.setAttributesToGet(value1.getAttributesToGet());
                        requests.add(new DynamoDBRequest(query, OP_READ));
                        i++;
                    }
                operation = new DynamoDBOperation(requests, klassName, "executeBatchGetItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof BatchWriteItemRequest) {
                BatchWriteItemRequest request = (BatchWriteItemRequest) value;
                for (Map.Entry<String, List<WriteRequest>> entry : request.getRequestItems().entrySet())
                    if (entry.getValue() != null)
                        for(WriteRequest item : entry.getValue()) {
                            if (item.getPutRequest() != null) {
                                PutRequest putRequest = item.getPutRequest();
                                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                                query.setItem(putRequest.getItem());
                                requests.add(new DynamoDBRequest(query, OP_WRITE));
                            }
                            if (item.getDeleteRequest() != null) {
                                DeleteRequest deleteRequest = item.getDeleteRequest();
                                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                                query.setKey(deleteRequest.getKey());
                                requests.add(new DynamoDBRequest(query, OP_DELETE));
                            }
                        }
                operation = new DynamoDBOperation(requests, klassName, "executeBatchWriteItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof DeleteItemRequest) {
                DeleteItemRequest request = (DeleteItemRequest) value;
                if (request.getConditionExpression() == null) {
                    return null;
                }
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setKey(request.getKey());
                query.setTableName(request.getTableName());
                query.setExpected(request.getExpected());
                query.setConditionExpression(request.getConditionExpression());
                query.setExpressionAttributeNames(request.getExpressionAttributeNames());
                query.setExpressionAttributeValues(request.getExpressionAttributeValues());
                requests.add(new DynamoDBRequest(query, OP_DELETE));
                operation = new DynamoDBOperation(requests, klassName, "executeDeleteItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof QueryRequest) {
                QueryRequest request = (QueryRequest) value;
                if (request.getFilterExpression() == null && request.getKeyConditionExpression() == null && request.getProjectionExpression() == null) {
                    return null;
                }
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.getTableName());
                query.setKeyConditionExpression(request.getKeyConditionExpression());
                query.setFilterExpression(request.getFilterExpression());
                query.setProjectionExpression(request.getProjectionExpression());
                query.setExpressionAttributeNames(request.getExpressionAttributeNames());
                query.setExpressionAttributeValues(request.getExpressionAttributeValues());
                query.setQueryFilter(request.getQueryFilter());
                query.setAttributesToGet(request.getAttributesToGet());
                requests.add(new DynamoDBRequest(query, OP_READ));
                operation = new DynamoDBOperation(requests, klassName, "executeQuery", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof GetItemRequest) {
                GetItemRequest request = (GetItemRequest) value;
                if (request.getProjectionExpression() == null) {
                    return null;
                }
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.getTableName());
                query.setKey(request.getKey());
                query.setProjectionExpression(request.getProjectionExpression());
                query.setExpressionAttributeNames(request.getExpressionAttributeNames());
                query.setAttributesToGet(request.getAttributesToGet());
                requests.add(new DynamoDBRequest(query, OP_READ));
                operation = new DynamoDBOperation(requests, klassName, "executeGetItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof PutItemRequest) {
                PutItemRequest request = (PutItemRequest) value;
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.getTableName());
                query.setItem(request.getItem());
                query.setExpected(request.getExpected());
                query.setConditionExpression(request.getConditionExpression());
                query.setExpressionAttributeNames(request.getExpressionAttributeNames());
                query.setExpressionAttributeValues(request.getExpressionAttributeValues());
                requests.add(new DynamoDBRequest(query, OP_WRITE));
                operation = new DynamoDBOperation(requests, klassName, "executePutItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof ScanRequest) {
                ScanRequest request = (ScanRequest) value;
                if (request.getProjectionExpression() == null && request.getFilterExpression() == null) {
                    return null;
                }
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.getTableName());
                query.setFilterExpression(request.getFilterExpression());
                query.setScanFilter(request.getScanFilter());
                query.setProjectionExpression(request.getProjectionExpression());
                query.setAttributesToGet(request.getAttributesToGet());
                query.setExpressionAttributeNames(request.getExpressionAttributeNames());
                query.setExpressionAttributeValues(request.getExpressionAttributeValues());
                requests.add(new DynamoDBRequest(query, OP_READ));
                operation = new DynamoDBOperation(requests, klassName, "executeScan", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof UpdateItemRequest) {
                UpdateItemRequest request = (UpdateItemRequest) value;
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.getTableName());
                query.setKey(request.getKey());
                query.setExpected(request.getExpected());
                query.setAttributeUpdates(request.getAttributeUpdates());
                query.setUpdateExpression(request.getUpdateExpression());
                query.setConditionExpression(request.getConditionExpression());
                query.setExpressionAttributeNames(request.getExpressionAttributeNames());
                query.setExpressionAttributeValues(request.getExpressionAttributeValues());
                requests.add(new DynamoDBRequest(query, OP_UPDATE));
                operation = new DynamoDBOperation(requests, klassName, "executeUpdateItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof TransactGetItemsRequest) {
                TransactGetItemsRequest request = (TransactGetItemsRequest) value;
                List<TransactGetItem> transactItems = request.getTransactItems();
                if (transactItems == null && transactItems.size() == 0) {
                    return null;
                }
                boolean generate = false;
                for (int i = 0; i < transactItems.size(); i++) {
                    if (transactItems.get(i).getGet() != null) {
                        if (transactItems.get(i).getGet().getProjectionExpression() != null) {
                            generate = true;
                        }
                        if (i + 1 == transactItems.size() && !generate) {
                            return null;
                        }
                        Get get = transactItems.get(i).getGet();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setKey(get.getKey());
                        query.setTableName(get.getTableName());
                        query.setExpressionAttributeNames(get.getExpressionAttributeNames());
                        query.setProjectionExpression(get.getProjectionExpression());
                        requests.add(new DynamoDBRequest(query, OP_READ));
                    }
                }
                operation = new DynamoDBOperation(requests, klassName, "transactGetItemsRequest", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof TransactWriteItemsRequest) {
                TransactWriteItemsRequest request = (TransactWriteItemsRequest) value;
                List<TransactWriteItem> transactItems = request.getTransactItems();
                for (int i=0; i< transactItems.size(); i++) {
                    if (transactItems.get(i).getConditionCheck() != null) {
                        ConditionCheck conditionCheck = transactItems.get(i).getConditionCheck();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setKey(conditionCheck.getKey());
                        query.setTableName(conditionCheck.getTableName());
                        query.setConditionExpression(conditionCheck.getConditionExpression());
                        query.setExpressionAttributeNames(conditionCheck.getExpressionAttributeNames());
                        query.setExpressionAttributeValues(conditionCheck.getExpressionAttributeValues());
                        requests.add(new DynamoDBRequest(query, OP_READ));
                    }
                    if (transactItems.get(i).getPut() != null) {
                        Put put = transactItems.get(i).getPut();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setItem(put.getItem());
                        query.setTableName(put.getTableName());
                        query.setConditionExpression(put.getConditionExpression());
                        query.setExpressionAttributeNames(put.getExpressionAttributeNames());
                        query.setExpressionAttributeValues(put.getExpressionAttributeValues());
                        requests.add(new DynamoDBRequest(query, OP_WRITE));
                    }
                    if (transactItems.get(i).getUpdate() != null) {
                        Update update = transactItems.get(i).getUpdate();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setKey(update.getKey());
                        query.setTableName(update.getTableName());
                        query.setConditionExpression(update.getConditionExpression());
                        query.setUpdateExpression(update.getUpdateExpression());
                        query.setExpressionAttributeNames(update.getExpressionAttributeNames());
                        query.setExpressionAttributeValues(update.getExpressionAttributeValues());
                        requests.add(new DynamoDBRequest(query, OP_UPDATE));
                    }
                    if (transactItems.get(i).getDelete() != null) {
                        Delete delete = transactItems.get(i).getDelete();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setKey(delete.getKey());
                        query.setTableName(delete.getTableName());
                        query.setConditionExpression(delete.getConditionExpression());
                        query.setExpressionAttributeNames(delete.getExpressionAttributeNames());
                        query.setExpressionAttributeValues(delete.getExpressionAttributeValues());
                        requests.add(new DynamoDBRequest(query, OP_DELETE));
                    }
                }
                operation = new DynamoDBOperation(requests, klassName, "transactWriteItemsRequest", DynamoDBOperation.Category.DQL);
            }

        } catch (Exception e) {
            String message = "Instrumentation library: %s , error while creating operation : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, DYNAMODB_1_11_459, e.getMessage()), e, DynamoDBUtil.class.getName());
        }
        return operation;
    }

}
