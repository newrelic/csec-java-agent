package com.mongodb.operation;

import com.mongodb.async.SingleResultCallback;
import com.mongodb.binding.AsyncReadBinding;
import com.mongodb.binding.ReadBinding;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.mongo.MongoUtil;
import org.bson.BsonDocument;

@Weave(type = MatchType.ExactClass, originalName = "com.mongodb.operation.CommandReadOperation")
public class CommandReadOperation_Instrumentation<T> {

    private final BsonDocument command = Weaver.callOriginal();

    public T execute(final ReadBinding binding) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = MongoUtil.acquireLockIfPossible(this.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.recordMongoOperation(command, MongoUtil.OP_READ, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
        }
        T returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
        } finally {
            if (isLockAcquired) {
                MongoUtil.releaseLock(this.hashCode());
            }
        }
        MongoUtil.registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }

    public void executeAsync(final AsyncReadBinding binding, final SingleResultCallback<T> callback) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = MongoUtil.acquireLockIfPossible(this.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.recordMongoOperation(command, MongoUtil.OP_READ, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
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
