package com.mongodb.operation;

import com.mongodb.ServerAddress;
import com.mongodb.async.SingleResultCallback;
import com.mongodb.binding.AsyncReadBinding;
import com.mongodb.binding.ReadBinding;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.mongo.MongoUtil;
import org.bson.BsonDocument;

import java.net.*;

@Weave(type = MatchType.ExactClass, originalName = "com.mongodb.operation.CommandReadOperation")
public class CommandReadOperation_Instrumentation<T> {

    private final BsonDocument command = Weaver.callOriginal();

    public T execute(final ReadBinding binding) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = MongoUtil.acquireLockIfPossible(this.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.recordMongoOperation(command, MongoUtil.OP_READ, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
            recordExternalConnection(binding);
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

    private static void recordExternalConnection(ReadBinding binding) {
        ServerAddress serverAddress = binding.getReadConnectionSource().getServerDescription().getAddress();
        String ipAddress = null;
        try {
            ipAddress = InetAddress.getByName(serverAddress.getHost()).getHostAddress();
        } catch (UnknownHostException ignored) {
        }
        NewRelicSecurity.getAgent().recordExternalConnection(serverAddress.getHost(), serverAddress.getPort(),
                serverAddress.toString(), ipAddress, ExternalConnectionType.DATABASE_CONNECTION.name(), MongoUtil.MONGODB_3_0);
    }

    public void executeAsync(final AsyncReadBinding binding, final SingleResultCallback<T> callback) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = MongoUtil.acquireLockIfPossible(this.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.recordMongoOperation(command, MongoUtil.OP_READ, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
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
