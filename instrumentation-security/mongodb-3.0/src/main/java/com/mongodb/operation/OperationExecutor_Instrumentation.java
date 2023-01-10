package com.mongodb.operation;

import com.mongodb.ReadPreference;
import com.mongodb.bulk.DeleteRequest;
import com.mongodb.bulk.InsertRequest;
import com.mongodb.bulk.UpdateRequest;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.NoSQLOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.agent.security.mongo.MongoUtil;
import org.bson.BsonDocument;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

@Weave(type = MatchType.Interface, originalName = "com.mongodb.operation.OperationExecutor")
public abstract class OperationExecutor_Instrumentation {

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
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

    private void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(MongoUtil.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible(int hashCode) {
        try {
            return GenericHelper.acquireLockIfPossible(MongoUtil.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
        } catch (Throwable ignored) {
        }
        return false;
    }

    private AbstractOperation recordMongoOperation(List<BsonDocument> command, String typeOfOperation, String methodName) {
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
                operation = new NoSQLOperation(operations, typeOfOperation, this.getClass().getName(), methodName);
                NewRelicSecurity.getAgent().registerOperation(operation);
            }
        } catch (Throwable e) {
            e.printStackTrace();
            if (e instanceof NewRelicSecurityException) {
                throw e;
            }
        }
        return operation;
    }

    private AbstractOperation recordMongoOperation(BsonDocument command, String typeOfOperation, String methodName) {
        NoSQLOperation operation = null;
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() && command != null) {
                operation = new NoSQLOperation(command, typeOfOperation, this.getClass().getName(), methodName);
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

    public <T> T execute(ReadOperation<T> operation, ReadPreference readPreference) {

        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = acquireLockIfPossible(operation.hashCode());
        if (isLockAcquired) {
            List<BsonDocument> operations;
            if (operation instanceof AggregateOperation) {
                AggregateOperation aggregateOperation = (AggregateOperation) operation;
                noSQLOperation = recordMongoOperation(aggregateOperation.getPipeline(), MongoUtil.OP_AGGREGATE, MongoUtil.METHOD_EXECUTE);
            } else if (operation instanceof CountOperation) {
                CountOperation countOperation = (CountOperation) operation;
                noSQLOperation = recordMongoOperation(countOperation.getFilter(), MongoUtil.OP_COUNT, MongoUtil.METHOD_EXECUTE);
            } else if (operation instanceof DistinctOperation) {
                DistinctOperation distinctOperation = (DistinctOperation) operation;
                noSQLOperation = recordMongoOperation(distinctOperation.getFilter(), MongoUtil.OP_DISTINCT, MongoUtil.METHOD_EXECUTE);
            } else if (operation instanceof FindOperation) {
                FindOperation findOperation = (FindOperation) operation;
                noSQLOperation = recordMongoOperation(findOperation.getFilter(), MongoUtil.OP_FIND, MongoUtil.METHOD_EXECUTE);
            } else if (operation instanceof GroupOperation) {
                GroupOperation groupOperation = (GroupOperation) operation;
                operations = new ArrayList<>();
                operations.add(groupOperation.getFilter());
                operations.add(groupOperation.getReduceFunction().asDocument());
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_FIND, MongoUtil.METHOD_EXECUTE);
            } else if (operation instanceof ListCollectionsOperation) {
                ListCollectionsOperation listCollectionsOperation = (ListCollectionsOperation) operation;
                noSQLOperation = recordMongoOperation(listCollectionsOperation.getFilter(), MongoUtil.OP_READ, MongoUtil.METHOD_EXECUTE);
            } else if (operation instanceof MapReduceWithInlineResultsOperation) {
                MapReduceWithInlineResultsOperation mapReduceWithInlineResultsOperation = (MapReduceWithInlineResultsOperation) operation;
                operations = new ArrayList<>();
                operations.add(mapReduceWithInlineResultsOperation.getFilter());
                operations.add(mapReduceWithInlineResultsOperation.getSort());
                operations.add(mapReduceWithInlineResultsOperation.getMapFunction().asDocument());
                operations.add(mapReduceWithInlineResultsOperation.getReduceFunction().asDocument());
                noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_MAP_REDUCE, MongoUtil.METHOD_EXECUTE);
            }
        }
        Object returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
        } finally {
            if (isLockAcquired) {
                releaseLock(operation.hashCode());
            }
        }
        registerExitOperation(isLockAcquired, noSQLOperation);
        return (T) returnVal;
    }

    public <T> T execute(WriteOperation<T> operation) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = acquireLockIfPossible(operation.hashCode());
        try {
            System.out.println("operation x instance : " + this.getClass().getName() + " " + operation.getClass());
            List<BsonDocument> operations;
            if (isLockAcquired) {
                if (operation instanceof AggregateToCollectionOperation) {
                    AggregateToCollectionOperation aggregateToCollectionOperation = (AggregateToCollectionOperation) operation;
                    noSQLOperation = recordMongoOperation(aggregateToCollectionOperation.getPipeline(), MongoUtil.OP_WRITE, MongoUtil.METHOD_EXECUTE);
                } else if (operation instanceof DeleteOperation) {
                    DeleteOperation deleteOperation = (DeleteOperation) operation;
                    operations = new ArrayList<>();
                    for (DeleteRequest deleteRequest : deleteOperation.getDeleteRequests()) {
                        operations.add(deleteRequest.getFilter());
                    }
                    noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_DELETE, MongoUtil.METHOD_EXECUTE);
                } else if (operation instanceof FindAndDeleteOperation) {
                    FindAndDeleteOperation findAndDeleteOperation = (FindAndDeleteOperation) operation;
                    operations = new ArrayList<>();
                    operations.add(findAndDeleteOperation.getFilter());
                    operations.add(findAndDeleteOperation.getProjection());
                    operations.add(findAndDeleteOperation.getSort());
                    noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_FIND_AND_DELETE, MongoUtil.METHOD_EXECUTE);
                } else if (operation instanceof FindAndReplaceOperation) {
                    FindAndReplaceOperation findAndReplaceOperation = (FindAndReplaceOperation) operation;
                    operations = new ArrayList<>();
                    operations.add(findAndReplaceOperation.getFilter());
                    operations.add(findAndReplaceOperation.getProjection());
                    operations.add(findAndReplaceOperation.getSort());
                    operations.add(findAndReplaceOperation.getReplacement());
                    noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_FIND_AND_REPLACE, MongoUtil.METHOD_EXECUTE);
                } else if (operation instanceof FindAndUpdateOperation) {
                    FindAndUpdateOperation findAndUpdateOperation = (FindAndUpdateOperation) operation;
                    operations = new ArrayList<>();
                    operations.add(findAndUpdateOperation.getFilter());
                    operations.add(findAndUpdateOperation.getProjection());
                    operations.add(findAndUpdateOperation.getSort());
                    operations.add(findAndUpdateOperation.getUpdate());
                    noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_FIND_AND_UPDATE, MongoUtil.METHOD_EXECUTE);
                } else if (operation instanceof InsertOperation) {
                    System.out.println("inside insert");
                    InsertOperation insertOperation = (InsertOperation) operation;
                    operations = new ArrayList<>();
                    for (InsertRequest insertRequest : insertOperation.getInsertRequests()) {
                        operations.add(insertRequest.getDocument());
                    }
                    System.out.println("inside insert : " + operations);
                    noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_INSERT, MongoUtil.METHOD_EXECUTE);
                } else if (operation instanceof MapReduceToCollectionOperation) {
                    MapReduceToCollectionOperation mapReduceToCollectionOperation = (MapReduceToCollectionOperation) operation;
                    operations = new ArrayList<>();
                    operations.add(mapReduceToCollectionOperation.getFilter());
                    operations.add(mapReduceToCollectionOperation.getMapFunction().asDocument());
                    operations.add(mapReduceToCollectionOperation.getReduceFunction().asDocument());
                    noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_MAP_REDUCE, MongoUtil.METHOD_EXECUTE);
                } else if (operation instanceof UpdateOperation) {
                    UpdateOperation updateOperation = (UpdateOperation) operation;
                    operations = new ArrayList<>();
                    for (UpdateRequest updateRequest : updateOperation.getUpdateRequests()) {
                        operations.add(updateRequest.getUpdate());
                        operations.add(updateRequest.getFilter());
                    }
                    noSQLOperation = recordMongoOperation(operations, MongoUtil.OP_UPDATE, MongoUtil.METHOD_EXECUTE);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        Object returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
        } finally {
            if (isLockAcquired) {
                releaseLock(operation.hashCode());
            }
        }
        registerExitOperation(isLockAcquired, noSQLOperation);
        return (T) returnVal;
    }
}
