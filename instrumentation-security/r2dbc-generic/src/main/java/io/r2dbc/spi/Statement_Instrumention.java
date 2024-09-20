package io.r2dbc.spi;

import com.newrelic.api.agent.security.instrumentation.helpers.R2dbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.reactivestreams.Publisher;

import java.util.HashMap;
import java.util.Map;

import static com.newrelic.api.agent.security.instrumentation.helpers.R2dbcHelper.releaseLock;

@Weave(type = MatchType.Interface, originalName = "io.r2dbc.spi.Statement")
public class Statement_Instrumention {
    @NewField
    String sql;
    @NewField
    private Map<String, String> params;
    @NewField
    private boolean isPrepared = false;
    @NewField
    private boolean lock = false;

    public Publisher<? extends Result> execute() {
        boolean isLockAcquired = R2dbcHelper.acquireLockIfPossible(VulnerabilityCaseType.SQL_DB_COMMAND);
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = R2dbcHelper.preprocessSecurityHook(sql, R2dbcHelper.METHOD_EXECUTE, this.getClass().getName(), params, isPrepared);
        }
        Publisher<? extends Result> returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock();
            }
        }
        R2dbcHelper.registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    public Statement bind(int index, Object value){
        if (!lock) {
            setParamValue(String.valueOf(index), value);
        }
        return Weaver.callOriginal();
    }

    public Statement bind(String index, Object value){
        Statement var1;
        try {
            setParamValue(index, value);
            lock = true;
            var1 = Weaver.callOriginal();
        } finally {
            lock = false;
        }
        return var1;
    }

    public Statement bindNull(int index, Class<?> type){
        if (!lock) {
            setParamValue(String.valueOf(index), type);
        }
        return Weaver.callOriginal();
    }

    public Statement bindNull(String index, Class<?> type) {
        Statement var1;
        try {
            setParamValue(index, type);
            lock = true;
            var1 = Weaver.callOriginal();
        } finally {
            lock = false;
        }
        return var1;
    }

    private void setParamValue(String index, Object value) {
        if (params == null) {
            params = new HashMap<>();
        }
        params.put(index, String.valueOf(value));
        isPrepared = true;
    }
}
