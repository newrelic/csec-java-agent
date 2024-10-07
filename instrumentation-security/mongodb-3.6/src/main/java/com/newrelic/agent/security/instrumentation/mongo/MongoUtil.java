/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.mongo;

import com.mongodb.bulk.DeleteRequest;
import com.mongodb.bulk.InsertRequest;
import com.mongodb.bulk.UpdateRequest;
import com.mongodb.bulk.WriteRequest;
import com.mongodb.operation.*;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.NoSQLOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.bson.BsonDocument;

import java.util.ArrayList;
import java.util.List;

public class MongoUtil {

    public static final String MONGODB_3_6 = "MONGODB-3.6";
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "MONGO_OPERATION_LOCK-";
    public static final String OP_READ = "read";

    public static final String OP_WRITE = "write";
    public static final String OP_FIND = "find";
    public static final String OP_INSERT = "insert";
    public static final String OP_UPDATE = "update";
    public static final String OP_AGGREGATE = "aggregate";
    public static final String OP_FIND_AND_DELETE = "findAndDelete";
    public static final String OP_DISTINCT = "distinct";
    public static final String OP_COUNT = "count";
    public static final String OP_MAP_REDUCE = "mapReduce";

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

    public static AbstractOperation recordMongoOperation(BsonDocument command, String typeOfOperation, String klassName, String methodName) {
        NoSQLOperation operation = null;
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() && command != null) {
                operation = new NoSQLOperation(command.toJson(), typeOfOperation, klassName, methodName);
                NewRelicSecurity.getAgent().registerOperation(operation);
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
        }
        return operation;
    }

    public static AbstractOperation recordMongoOperation(List<BsonDocument> command, String typeOfOperation, String klassName, String methodName) {
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
                NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(4);
                NewRelicSecurity.getAgent().registerOperation(operation);
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
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
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
        }
    }

    public static void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(MongoUtil.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
    }

    public static boolean acquireLockIfPossible(VulnerabilityCaseType nosqlDbCommand, int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(nosqlDbCommand, MongoUtil.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
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
                NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(4);
                NewRelicSecurity.getAgent().registerOperation(operation);
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e, MongoUtil.class.getName());
        }
        return operation;
    }

    public static <T> AbstractOperation getReadAbstractOperation(ReadOperation<T> operation, String className, String methodName) {
        AbstractOperation noSQLOperation = null;
        try {
            List<BsonDocument> operations;
            if (operation instanceof AggregateOperation) {
                AggregateOperation aggregateOperation = (AggregateOperation) operation;
                noSQLOperation = recordMongoOperation(aggregateOperation.getPipeline(), MongoUtil.OP_AGGREGATE, className, methodName);
            } else if (operation instanceof CountOperation) {
                CountOperation countOperation = (CountOperation) operation;
                noSQLOperation = recordMongoOperation(countOperation.getFilter(), MongoUtil.OP_COUNT, className, methodName);
            } else if (operation instanceof DistinctOperation) {
                DistinctOperation distinctOperation = (DistinctOperation) operation;
                noSQLOperation = recordMongoOperation(distinctOperation.getFilter(), MongoUtil.OP_DISTINCT, className, methodName);
            } else if (operation instanceof FindOperation) {
                FindOperation findOperation = (FindOperation) operation;
                noSQLOperation = recordMongoOperation(findOperation.getFilter(), MongoUtil.OP_FIND, className, methodName);
            } else if (operation instanceof GroupOperation) {
                GroupOperation groupOperation = (GroupOperation) operation;
                operations = new ArrayList<>();
                operations.add(groupOperation.getFilter());
                operations.add(groupOperation.getReduceFunction().asDocument());
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_FIND, className, methodName);
            } else if (operation instanceof ListCollectionsOperation) {
                ListCollectionsOperation listCollectionsOperation = (ListCollectionsOperation) operation;
                noSQLOperation = recordMongoOperation(listCollectionsOperation.getFilter(), MongoUtil.OP_READ, className, methodName);
            } else if (operation instanceof MapReduceWithInlineResultsOperation) {
                MapReduceWithInlineResultsOperation mapReduceWithInlineResultsOperation = (MapReduceWithInlineResultsOperation) operation;
                operations = new ArrayList<>();
                operations.add(mapReduceWithInlineResultsOperation.getFilter());
                operations.add(mapReduceWithInlineResultsOperation.getSort());
                operations.add(mapReduceWithInlineResultsOperation.getMapFunction().asDocument());
                operations.add(mapReduceWithInlineResultsOperation.getReduceFunction().asDocument());
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_MAP_REDUCE, className, methodName);
            }
        } catch (Exception e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent()
                        .log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e,
                                MongoUtil.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent()
                    .log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e,
                            MongoUtil.class.getName());
            NewRelicSecurity.getAgent()
                    .reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e,
                            MongoUtil.class.getName());
        }
        return noSQLOperation;
    }

    public static <T> AbstractOperation getWriteAbstractOperation(WriteOperation<T> operation, String className, String methodName) {
        AbstractOperation noSQLOperation = null;
        try {
            List<BsonDocument> operations;
            if (operation instanceof AggregateToCollectionOperation) {
                AggregateToCollectionOperation aggregateToCollectionOperation = (AggregateToCollectionOperation) operation;
                noSQLOperation = recordMongoOperation(aggregateToCollectionOperation.getPipeline(), MongoUtil.OP_WRITE, className, methodName);
            } else if (operation instanceof DeleteOperation) {
                DeleteOperation deleteOperation = (DeleteOperation) operation;
                operations = new ArrayList<>();
                for (DeleteRequest deleteRequest : deleteOperation.getDeleteRequests()) {
                    operations.add(deleteRequest.getFilter());
                }
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_DELETE, className, methodName);
            } else if (operation instanceof FindAndDeleteOperation) {
                FindAndDeleteOperation findAndDeleteOperation = (FindAndDeleteOperation) operation;
                operations = new ArrayList<>();
                operations.add(findAndDeleteOperation.getFilter());
                operations.add(findAndDeleteOperation.getProjection());
                operations.add(findAndDeleteOperation.getSort());
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_FIND_AND_DELETE, className, methodName);
            } else if (operation instanceof FindAndReplaceOperation) {
                FindAndReplaceOperation findAndReplaceOperation = (FindAndReplaceOperation) operation;
                operations = new ArrayList<>();
                operations.add(findAndReplaceOperation.getFilter());
                operations.add(findAndReplaceOperation.getProjection());
                operations.add(findAndReplaceOperation.getSort());
                operations.add(findAndReplaceOperation.getReplacement());
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_WRITE, className, methodName);
            } else if (operation instanceof FindAndUpdateOperation) {
                FindAndUpdateOperation findAndUpdateOperation = (FindAndUpdateOperation) operation;
                operations = new ArrayList<>();
                operations.add(findAndUpdateOperation.getFilter());
                operations.add(findAndUpdateOperation.getProjection());
                operations.add(findAndUpdateOperation.getSort());
                operations.add(findAndUpdateOperation.getUpdate());
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_WRITE, className, methodName);
            } else if (operation instanceof InsertOperation) {
                InsertOperation insertOperation = (InsertOperation) operation;
                operations = new ArrayList<>();
                for (InsertRequest insertRequest : insertOperation.getInsertRequests()) {
                    operations.add(insertRequest.getDocument());
                }
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_INSERT, className, methodName);
            } else if (operation instanceof MapReduceToCollectionOperation) {
                MapReduceToCollectionOperation mapReduceToCollectionOperation = (MapReduceToCollectionOperation) operation;
                operations = new ArrayList<>();
                operations.add(mapReduceToCollectionOperation.getFilter());
                operations.add(mapReduceToCollectionOperation.getMapFunction().asDocument());
                operations.add(mapReduceToCollectionOperation.getReduceFunction().asDocument());
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_MAP_REDUCE, className, methodName);
            } else if (operation instanceof UpdateOperation) {
                UpdateOperation updateOperation = (UpdateOperation) operation;
                operations = new ArrayList<>();
                for (UpdateRequest updateRequest : updateOperation.getUpdateRequests()) {
                    operations.add(updateRequest.getUpdate());
                    operations.add(updateRequest.getFilter());
                }
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_UPDATE, className, methodName);
            } else if (operation instanceof MixedBulkWriteOperation) {
                MixedBulkWriteOperation mixedBulkWriteOperation = (MixedBulkWriteOperation) operation;
                noSQLOperation = MongoUtil.recordWriteRequest(mixedBulkWriteOperation.getWriteRequests(), className, methodName);
            }
        } catch (Exception e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent()
                        .log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e,
                                MongoUtil.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent()
                    .log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e,
                            MongoUtil.class.getName());
            NewRelicSecurity.getAgent()
                    .reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MONGODB_3_6, e.getMessage()), e,
                            MongoUtil.class.getName());
        }
        return noSQLOperation;
    }
}
