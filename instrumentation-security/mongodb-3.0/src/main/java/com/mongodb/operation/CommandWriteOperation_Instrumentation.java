package com.mongodb.operation;

import com.mongodb.async.SingleResultCallback;
import com.mongodb.binding.AsyncWriteBinding;
import com.mongodb.binding.WriteBinding;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.mongo.MongoUtil;
import org.bson.BsonDocument;

@Weave(type = MatchType.ExactClass, originalName = "com.mongodb.operation.CommandWriteOperation")
public class CommandWriteOperation_Instrumentation<T> {

    private final BsonDocument command = Weaver.callOriginal();

    public T execute(final WriteBinding binding) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = MongoUtil.acquireLockIfPossible(VulnerabilityCaseType.NOSQL_DB_COMMAND, this.hashCode());
        if (NewRelicSecurity.isHookProcessingActive()){
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
        }
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.recordMongoOperation(command, MongoUtil.OP_WRITE, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
        }
        T returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                MongoUtil.releaseLock(this.hashCode());
            }
        }
        MongoUtil.registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }

    public void executeAsync(final AsyncWriteBinding binding, final SingleResultCallback<T> callback) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = MongoUtil.acquireLockIfPossible(VulnerabilityCaseType.NOSQL_DB_COMMAND, this.hashCode());
        if (NewRelicSecurity.isHookProcessingActive()){
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
        }
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.recordMongoOperation(command, MongoUtil.OP_WRITE, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                MongoUtil.releaseLock(this.hashCode());
            }
        }
        MongoUtil.registerExitOperation(isLockAcquired, noSQLOperation);
    }

}
