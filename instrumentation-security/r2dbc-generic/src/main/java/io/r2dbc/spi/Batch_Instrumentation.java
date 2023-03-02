package io.r2dbc.spi;

import com.newrelic.api.agent.security.instrumentation.helpers.R2dbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.reactivestreams.Publisher;

@Weave(type = MatchType.Interface, originalName = "io.r2dbc.spi.Batch")
public class Batch_Instrumentation {
    @NewField
    String sql;

    public Batch add(String s){
        sql = s;
        return Weaver.callOriginal();
    }

    public Publisher<? extends Result> execute() {
        boolean isLockAcquired = R2dbcHelper.acquireLockIfPossible();
        AbstractOperation operation = null;
        if (isLockAcquired) {
            operation = R2dbcHelper.preprocessSecurityHook(sql, R2dbcHelper.METHOD_EXECUTE, this.getClass().getName(), null, false);
        }
        Publisher<? extends Result> returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                R2dbcHelper.releaseLock();
            }
        }
        R2dbcHelper.registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }
}
