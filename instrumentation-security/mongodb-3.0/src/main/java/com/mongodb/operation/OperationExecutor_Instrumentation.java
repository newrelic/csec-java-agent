package com.mongodb.operation;

import com.mongodb.ReadPreference;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.mongo.MongoUtil;

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
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, MongoUtil.MONGODB_3_0, e.getMessage()), e, OperationExecutor_Instrumentation.class.getName());
        }
    }

    private void releaseLock(int hashCode) {
        GenericHelper.releaseLock(MongoUtil.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType nosqlDbCommand, int hashCode) {
        return GenericHelper.acquireLockIfPossible(nosqlDbCommand, MongoUtil.NR_SEC_CUSTOM_ATTRIB_NAME, hashCode);
    }

    public <T> T execute(ReadOperation<T> operation, ReadPreference readPreference) {

        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.getReadAbstractOperation(operation, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
        }
        T returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(operation.hashCode());
            }
        }
        registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }

    public <T> T execute(WriteOperation<T> operation) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.getWriteAbstractOperation(operation, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
        }

        T returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(operation.hashCode());
            }
        }
        registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }
}
