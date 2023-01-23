/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.mongo;

import com.mongodb.bulk.DeleteRequest;
import com.mongodb.bulk.InsertRequest;
import com.mongodb.bulk.UpdateRequest;
import com.mongodb.bulk.WriteRequest;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.NoSQLOperation;
import org.bson.BsonDocument;

import java.util.ArrayList;
import java.util.List;

public class MongoUtil {


    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "MONGO_OPERATION_LOCK-";
    public static final String OP_READ = "read";
    public static final String OP_WRITE = "write";
    public static final String OP_FIND = "find";
    public static final String OP_INSERT = "insert";
    public static final String OP_UPDATE = "update";
    public static final String OP_AGGREGATE = "aggregate";
    public static final String OP_REMOVE = "remove";
    public static final String OP_PARALLEL_SCAN = "parallelCollectionScan";
    public static final String OP_CREATE_INDEX = "createIndex";

    public static final String OP_RENAME_COLLECTION = "renameCollection";
    public static final String OP_FIND_AND_UPDATE = "findAndUpdate";
    public static final String OP_FIND_AND_REPLACE = "findAndReplace";
    public static final String OP_FIND_AND_DELETE = "findAndDelete";
    public static final String OP_DROP_INDEX = "dropIndex";
    public static final String OP_DROP_COLLECTION = "drop";
    public static final String OP_DISTINCT = "distinct";
    public static final String OP_COUNT = "count";
    public static final String OP_MAP_REDUCE = "mapReduce";
    public static final String OP_REPLACE = "replace";
    public static final String OP_LIST_INDEX = "listIndex";
    public static final String OP_BULK_WRITE = "bulkWrite";
    public static final String OP_INSERT_MANY = "insertMany";
    public static final String OP_UPDATE_MANY = "updateMany";
    public static final String OP_GET_MORE = "getMore";

    // "delete" commands are different from DBCollection.remove
    public static final String OP_DELETE = "delete";

    /**
     * What to use when you can't get the operation.
     */
    public static final String DEFAULT_OPERATION = "other";

    /**
     * What to use when you can't get the collection name.
     */
    public static final String DEFAULT_COLLECTION = "other";

    public static final String OP_DEFAULT = "other";
    public static final String METHOD_EXECUTE = "execute";
    public static final String METHOD_EXECUTE_WRAPPED_COMMAND_PROTOCOL = "executeWrappedCommandProtocol";

    public static AbstractOperation recordMongoOperation(BsonDocument command, String typeOfOperation, String methodName, String klassName) {
        NoSQLOperation operation = null;
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() && command != null) {
                operation = new NoSQLOperation(command.toJson(), typeOfOperation, klassName, methodName);
                NewRelicSecurity.getAgent().registerOperation(operation);
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
        return operation;
    }

    public static AbstractOperation recordMongoOperation(List<BsonDocument> command, String typeOfOperation, String methodName, String klassName) {
        NoSQLOperation operation = null;
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                List<String> operations = new ArrayList<>();
                for (BsonDocument cmd : command) {
                    if(cmd != null) {
                        operations.add(cmd.toJson());
                    }
                }
                operation = new NoSQLOperation(operations, typeOfOperation, klassName, methodName);
                NewRelicSecurity.getAgent().registerOperation(operation);
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
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
            GenericHelper.releaseLock(MongoUtil.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
    }

    public static boolean acquireLockIfPossible(int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(MongoUtil.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static AbstractOperation recordWriteRequest(List<? extends WriteRequest> writeRequest, String klassName, String methodName) {
        NoSQLOperation operation = null;
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                List<String> operations = new ArrayList<>();
                for (WriteRequest request : writeRequest) {
                    if(request instanceof InsertRequest){
                        InsertRequest insertRequest = (InsertRequest) request;
                        operations.add(insertRequest.getDocument().toJson());
                    } else if (request instanceof DeleteRequest){
                        DeleteRequest deleteRequest = (DeleteRequest) request;
                        operations.add(deleteRequest.getFilter().toJson());
                    } else if (request instanceof UpdateRequest){
                        UpdateRequest updateRequest = (UpdateRequest) request;
                        operations.add(updateRequest.getUpdate().toJson());
                        operations.add(updateRequest.getFilter().toJson());
                    }
                }
                operation = new NoSQLOperation(operations, OP_WRITE, klassName, methodName);
                NewRelicSecurity.getAgent().registerOperation(operation);
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return operation;
    }
}
