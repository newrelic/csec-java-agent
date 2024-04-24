/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.dynamodb_215;

import com.newrelic.api.agent.DatastoreParameters;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.helper.DynamoDBRequest;
import com.newrelic.api.agent.security.schema.operation.DynamoDBOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import software.amazon.awssdk.core.SdkRequest;
import software.amazon.awssdk.core.SdkResponse;
import software.amazon.awssdk.core.client.handler.ClientExecutionParams;
import software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ConditionCheck;
import software.amazon.awssdk.services.dynamodb.model.Delete;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteTransactionRequest;
import software.amazon.awssdk.services.dynamodb.model.Get;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.ParameterizedStatement;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItem;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.Update;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.WriteRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    public static final String DYNAMODB_2_15_34 = "DYNAMODB-2.15.34";

    public static <InputT extends SdkRequest, OutputT extends SdkResponse> AbstractOperation processDynamoDBRequest(
            ClientExecutionParams<InputT, OutputT> yRequest, String klassName) {
        DynamoDBOperation operation = null;
        try {
            if (NewRelicSecurity.isHookProcessingActive() && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                List<DynamoDBRequest> requests = new ArrayList();
                InputT request = yRequest.getInput();

                operation = checkAndGenerateOperation(request, requests, klassName);

                if (operation!=null) {
                    NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
                    NewRelicSecurity.getAgent().registerOperation(operation);
                }
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, DYNAMODB_2_15_34, e.getMessage()), e, DynamoDBUtil.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, DYNAMODB_2_15_34, e.getMessage()), e, DynamoDBUtil.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, DYNAMODB_2_15_34, e.getMessage()), e, DynamoDBUtil.class.getName());
        }
        return operation;
    }

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, DYNAMODB_2_15_34, ignored.getMessage()), ignored, DynamoDBUtil.class.getName());
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
    private static <InputT> DynamoDBOperation checkAndGenerateOperation(InputT value, List<DynamoDBRequest> requests, String klassName) {
        DynamoDBOperation operation = null;
        try {
            if (value instanceof BatchGetItemRequest) {
                BatchGetItemRequest request = (BatchGetItemRequest) value;
                Map<String, KeysAndAttributes> requestItems = request.requestItems();
                boolean generate = false;
                int i = 0;
                Set<Map.Entry<String, KeysAndAttributes>> entries = requestItems.entrySet();
                for (Map.Entry<String, KeysAndAttributes> entry : entries)
                    if (entry.getValue() != null) {
                        KeysAndAttributes value1 = entry.getValue();
                        if (value1.projectionExpression() != null) {
                            generate = true;
                        }
                        if (i + 1 == entries.size() && !generate) {
                            return null;
                        }
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setTableName(entry.getKey());
                        query.setKey(value1.keys());
                        query.setProjectionExpression(value1.projectionExpression());
                        query.setExpressionAttributeNames(value1.expressionAttributeNames());
                        query.setAttributesToGet(value1.attributesToGet());
                        requests.add(new DynamoDBRequest(query, OP_READ));
                        i++;
                    }
                operation = new DynamoDBOperation(requests, klassName, "executeBatchGetItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof BatchWriteItemRequest) {
                BatchWriteItemRequest request = (BatchWriteItemRequest) value;
                for (Map.Entry<String, List<WriteRequest>> entry : request.requestItems().entrySet())
                    if (entry.getValue() != null)
                        for(WriteRequest item : entry.getValue()) {
                            if (item.putRequest() != null) {
                                PutRequest putRequest = item.putRequest();
                                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                                query.setItem(putRequest.item());
                                query.setTableName(entry.getKey());
                                requests.add(new DynamoDBRequest(query, OP_WRITE));
                            }
                            if (item.deleteRequest() != null) {
                                DeleteRequest deleteRequest = item.deleteRequest();
                                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                                query.setKey(deleteRequest.key());
                                query.setTableName(entry.getKey());
                                requests.add(new DynamoDBRequest(query, OP_DELETE));
                            }
                        }
                operation = new DynamoDBOperation(requests, klassName, "executeBatchWriteItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof DeleteItemRequest) {
                DeleteItemRequest request = (DeleteItemRequest) value;
                if (request.conditionExpression() == null) {
                    return null;
                }
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setKey(request.key());
                query.setTableName(request.tableName());
                query.setExpected(request.expected());
                query.setConditionExpression(request.conditionExpression());
                query.setExpressionAttributeNames(request.expressionAttributeNames());
                query.setExpressionAttributeValues(request.expressionAttributeValues());
                requests.add(new DynamoDBRequest(query, OP_DELETE));
                operation = new DynamoDBOperation(requests, klassName, "executeDeleteItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof QueryRequest) {
                QueryRequest request = (QueryRequest) value;
                if (request.filterExpression() == null && request.keyConditionExpression() == null && request.projectionExpression() == null) {
                    return null;
                }
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.tableName());
                query.setKeyConditionExpression(request.keyConditionExpression());
                query.setFilterExpression(request.filterExpression());
                query.setProjectionExpression(request.projectionExpression());
                query.setExpressionAttributeNames(request.expressionAttributeNames());
                query.setExpressionAttributeValues(request.expressionAttributeValues());
                query.setQueryFilter(request.queryFilter());
                query.setAttributesToGet(request.attributesToGet());
                requests.add(new DynamoDBRequest(query, OP_READ));
                operation = new DynamoDBOperation(requests, klassName, "executeQuery", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof GetItemRequest) {
                GetItemRequest request = (GetItemRequest) value;
                if (request.projectionExpression() == null) {
                    return null;
                }
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.tableName());
                query.setKey(request.key());
                query.setProjectionExpression(request.projectionExpression());
                query.setExpressionAttributeNames(request.expressionAttributeNames());
                query.setAttributesToGet(request.attributesToGet());
                requests.add(new DynamoDBRequest(query, OP_READ));
                operation = new DynamoDBOperation(requests, klassName, "executeGetItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof PutItemRequest) {
                PutItemRequest request = (PutItemRequest) value;
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.tableName());
                query.setItem(request.item());
                query.setExpected(request.expected());
                query.setConditionExpression(request.conditionExpression());
                query.setExpressionAttributeNames(request.expressionAttributeNames());
                query.setExpressionAttributeValues(request.expressionAttributeValues());
                requests.add(new DynamoDBRequest(query, OP_WRITE));
                operation = new DynamoDBOperation(requests, klassName, "executePutItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof ScanRequest) {
                ScanRequest request = (ScanRequest) value;
                if (request.projectionExpression() == null && request.filterExpression() == null) {
                    return null;
                }
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.tableName());
                query.setFilterExpression(request.filterExpression());
                query.setScanFilter(request.scanFilter());
                query.setProjectionExpression(request.projectionExpression());
                query.setAttributesToGet(request.attributesToGet());
                query.setExpressionAttributeNames(request.expressionAttributeNames());
                query.setExpressionAttributeValues(request.expressionAttributeValues());
                requests.add(new DynamoDBRequest(query, OP_READ));
                operation = new DynamoDBOperation(requests, klassName, "executeScan", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof UpdateItemRequest) {
                UpdateItemRequest request = (UpdateItemRequest) value;
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setTableName(request.tableName());
                query.setKey(request.key());
                query.setExpected(request.expected());
                query.setAttributeUpdates(request.attributeUpdates());
                query.setUpdateExpression(request.updateExpression());
                query.setConditionExpression(request.conditionExpression());
                query.setExpressionAttributeNames(request.expressionAttributeNames());
                query.setExpressionAttributeValues(request.expressionAttributeValues());
                requests.add(new DynamoDBRequest(query, OP_UPDATE));
                operation = new DynamoDBOperation(requests, klassName, "executeUpdateItem", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof TransactGetItemsRequest) {
                TransactGetItemsRequest request = (TransactGetItemsRequest) value;
                List<TransactGetItem> transactItems = request.transactItems();
                if (transactItems == null && transactItems.size() == 0) {
                    return null;
                }
                boolean generate = false;
                for (int i = 0; i < transactItems.size(); i++) {
                    if (transactItems.get(i).get() != null) {
                        if (transactItems.get(i).get().projectionExpression() != null) {
                            generate = true;
                        }
                        if (i + 1 == transactItems.size() && !generate) {
                            return null;
                        }
                        Get get = transactItems.get(i).get();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setKey(get.key());
                        query.setTableName(get.tableName());
                        query.setExpressionAttributeNames(get.expressionAttributeNames());
                        query.setProjectionExpression(get.projectionExpression());
                        requests.add(new DynamoDBRequest(query, OP_READ));
                    }
                }
                operation = new DynamoDBOperation(requests, klassName, "transactGetItems", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof TransactWriteItemsRequest) {
                TransactWriteItemsRequest request = (TransactWriteItemsRequest) value;
                List<TransactWriteItem> transactItems = request.transactItems();
                for (int i = 0; i < transactItems.size(); i++) {
                    if (transactItems.get(i).conditionCheck() != null) {
                        ConditionCheck conditionCheck = transactItems.get(i).conditionCheck();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setKey(conditionCheck.key());
                        query.setTableName(conditionCheck.tableName());
                        query.setConditionExpression(conditionCheck.conditionExpression());
                        query.setExpressionAttributeNames(conditionCheck.expressionAttributeNames());
                        query.setExpressionAttributeValues(conditionCheck.expressionAttributeValues());
                        requests.add(new DynamoDBRequest(query, OP_READ));
                    }
                    if (transactItems.get(i).put() != null) {
                        Put put = transactItems.get(i).put();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setItem(put.item());
                        query.setTableName(put.tableName());
                        query.setConditionExpression(put.conditionExpression());
                        query.setExpressionAttributeNames(put.expressionAttributeNames());
                        query.setExpressionAttributeValues(put.expressionAttributeValues());
                        requests.add(new DynamoDBRequest(query, OP_WRITE));
                    }
                    if (transactItems.get(i).update() != null) {
                        Update update = transactItems.get(i).update();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setKey(update.key());
                        query.setTableName(update.tableName());
                        query.setConditionExpression(update.conditionExpression());
                        query.setUpdateExpression(update.updateExpression());
                        query.setExpressionAttributeNames(update.expressionAttributeNames());
                        query.setExpressionAttributeValues(update.expressionAttributeValues());
                        requests.add(new DynamoDBRequest(query, OP_UPDATE));
                    }
                    if (transactItems.get(i).delete() != null) {
                        Delete delete = transactItems.get(i).delete();
                        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                        query.setKey(delete.key());
                        query.setTableName(delete.tableName());
                        query.setConditionExpression(delete.conditionExpression());
                        query.setExpressionAttributeNames(delete.expressionAttributeNames());
                        query.setExpressionAttributeValues(delete.expressionAttributeValues());
                        requests.add(new DynamoDBRequest(query, OP_DELETE));
                    }
                }
                operation = new DynamoDBOperation(requests, klassName, "transactWriteItems", DynamoDBOperation.Category.DQL);
            }
            else if (value instanceof ExecuteStatementRequest) {
                ExecuteStatementRequest request = (ExecuteStatementRequest) value;
                DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                query.setStatement(request.statement());
                query.setParameters(request.parameters());
                requests.add(new DynamoDBRequest(query, OP_READ_WRITE));
                operation = new DynamoDBOperation(requests, klassName, "executeStatement", DynamoDBOperation.Category.PARTIQL);
            }
            else if (value instanceof BatchExecuteStatementRequest) {
                BatchExecuteStatementRequest request = (BatchExecuteStatementRequest) value;
                for (BatchStatementRequest batchStatementRequest : request.statements()) {
                    DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                    query.setStatement(batchStatementRequest.statement());
                    query.setParameters(batchStatementRequest.parameters());
                    requests.add(new DynamoDBRequest(query, OP_READ_WRITE));
                }
                operation = new DynamoDBOperation(requests, klassName, "batchExecuteStatement", DynamoDBOperation.Category.PARTIQL);
            }
            else if (value instanceof ExecuteTransactionRequest) {
                ExecuteTransactionRequest request = (ExecuteTransactionRequest) value;
                for (ParameterizedStatement transactStatement : request.transactStatements()) {
                    DynamoDBRequest.Query query = new DynamoDBRequest.Query();
                    query.setStatement(transactStatement.statement());
                    query.setParameters(transactStatement.parameters());
                    requests.add(new DynamoDBRequest(query, OP_READ_WRITE));
                }
                operation = new DynamoDBOperation(requests, klassName, "executeTransaction", DynamoDBOperation.Category.PARTIQL);
            }
        } catch (Exception e) {
            String message = "Instrumentation library: %s , error while creating operation : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, DYNAMODB_2_15_34, e.getMessage()), e, DynamoDBUtil.class.getName());
        }
        return operation;
    }
}
