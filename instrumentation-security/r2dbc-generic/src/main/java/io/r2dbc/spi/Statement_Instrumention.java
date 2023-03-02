package io.r2dbc.spi;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.R2dbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.reactivestreams.Publisher;

import java.util.HashMap;
import java.util.Map;

@Weave(type = MatchType.Interface, originalName = "io.r2dbc.spi.Statement")
public class Statement_Instrumention {
    @NewField
    String sql;
    @NewField
    private Map<String, String> params;
    @NewField
    private boolean isPrepared = false;

    public Publisher<? extends Result> execute() {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = preprocessSecurityHook(sql, R2dbcHelper.METHOD_EXECUTE);
        }
        Publisher<? extends Result> returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public Statement bind(int index, Object value){
        setParamValue(String.valueOf(index), value);
        return Weaver.callOriginal();
    }

    public Statement bind(String index, Object value){
        setParamValue(index, value);
        return Weaver.callOriginal();
    }

    public Statement bindNull(int index, Class<?> type){
        setParamValue(String.valueOf(index), type);
        return Weaver.callOriginal();
    }

    public Statement bindNull(String index, Class<?> type){
        setParamValue(index, type);
        return Weaver.callOriginal();
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || R2dbcHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored) {
        }
    }

    private AbstractOperation preprocessSecurityHook(String sql, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
                    sql == null || sql.trim().isEmpty()) {
                return null;
            }
            SQLOperation sqlOperation = new SQLOperation(this.getClass().getName(), methodName);
            sqlOperation.setQuery(sql);
            sqlOperation.setDbName(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, String.class));

            sqlOperation.setPreparedCall(isPrepared);
            sqlOperation.setParams(params);

            NewRelicSecurity.getAgent().registerOperation(sqlOperation);
            return sqlOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }

    private void releaseLock() {
        try {
            R2dbcHelper.releaseLock();
        } catch (Throwable ignored) {
        }
    }

    private boolean acquireLockIfPossible() {
        try {
            return R2dbcHelper.acquireLockIfPossible();
        } catch (Throwable ignored) {
        }
        return false;
    }

    private void setParamValue(String index, Object value) {
        if (params == null) {
            params = new HashMap<>();
        }
        params.put(index, String.valueOf(value));
        isPrepared = true;
    }
}
