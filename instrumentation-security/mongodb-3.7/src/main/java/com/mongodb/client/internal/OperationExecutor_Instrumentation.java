package com.mongodb.client.internal;

import com.mongodb.ReadPreference;
import com.mongodb.bulk.*;
import com.mongodb.lang.Nullable;
import com.mongodb.operation.*;
import com.mongodb.session.ClientSession;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.NoSQLOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.agent.security.mongo.MongoUtil;
import org.bson.BsonDocument;

import java.util.ArrayList;
import java.util.List;

@Weave(type = MatchType.Interface, originalName = "com.mongodb.client.internal.OperationExecutor")
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

    public <T> T execute(ReadOperation<T> operation, ReadPreference readPreference, @Nullable ClientSession session) {
        System.out.println("operation instance : " + operation.getClass());

        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = acquireLockIfPossible(operation.hashCode());
        System.out.println("is lock acquired : "+isLockAcquired+ " , "+operation.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.getReadAbstractOperation(operation, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
        }
        T returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
        } finally {
            if (isLockAcquired) {
                releaseLock(operation.hashCode());
            }
        }
        registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }

    public <T> T execute(ReadOperation<T> operation, ReadPreference readPreference) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = acquireLockIfPossible(operation.hashCode());
        if (isLockAcquired) {
            noSQLOperation = MongoUtil.getReadAbstractOperation(operation, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
        }
        T returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
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
        boolean isLockAcquired = acquireLockIfPossible(operation.hashCode());
        try {
            if (isLockAcquired) {
                noSQLOperation = MongoUtil.getWriteAbstractOperation(operation, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        T returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
        } finally {
            if (isLockAcquired) {
                releaseLock(operation.hashCode());
            }
        }
        registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }

    public <T> T execute(WriteOperation<T> operation, @Nullable ClientSession session) {
        AbstractOperation noSQLOperation = null;
        boolean isLockAcquired = acquireLockIfPossible(operation.hashCode());
        try {
            if (isLockAcquired) {
                noSQLOperation = MongoUtil.getWriteAbstractOperation(operation, this.getClass().getName(), MongoUtil.METHOD_EXECUTE);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        T returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } catch (Throwable ignored) {
        } finally {
            if (isLockAcquired) {
                releaseLock(operation.hashCode());
            }
        }
        registerExitOperation(isLockAcquired, noSQLOperation);
        return returnVal;
    }

}
