package com.mongodb.operation;

import com.mongodb.async.SingleResultCallback;
import com.mongodb.binding.AsyncWriteBinding;
import com.mongodb.binding.WriteBinding;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.agent.security.mongo.MongoUtil;
import org.bson.BsonDocument;

@Weave(type = MatchType.ExactClass, originalName = "com.mongodb.operation.CommandWriteOperation")
public class CommandWriteOperation_Instrumentation<T> {

    private final BsonDocument command = Weaver.callOriginal();

    public T execute(final WriteBinding binding) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = MongoUtil.acquireLockIfPossible(this.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.recordMongoOperation(command, MongoUtil.OP_WRITE, MongoUtil.METHOD_EXECUTE, this.getClass().getName());
        }
        Object returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
        } finally {
            if (isLockAcquired) {
                MongoUtil.releaseLock(this.hashCode());
            }
        }
        MongoUtil.registerExitOperation(isLockAcquired, noSQLOperation);
        return (T) returnVal;
    }

    public void executeAsync(final AsyncWriteBinding binding, final SingleResultCallback<T> callback) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = MongoUtil.acquireLockIfPossible(this.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.recordMongoOperation(command, MongoUtil.OP_WRITE, MongoUtil.METHOD_EXECUTE, this.getClass().getName());
        }
        try {
            Weaver.callOriginal();
        } catch (Throwable ignored) {
        } finally {
            if (isLockAcquired) {
                MongoUtil.releaseLock(this.hashCode());
            }
        }
        MongoUtil.registerExitOperation(isLockAcquired, noSQLOperation);
    }

}
