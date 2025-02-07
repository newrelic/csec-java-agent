package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.Map;

public class R2dbcHelper {
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "R2DBC_OPERATION_LOCK-";
    public static final String METHOD_EXECUTE = "execute";
    public static final String R2DBC_GENERIC = "R2DBC-GENERIC";

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, R2DBC_GENERIC, e.getMessage()), e, R2dbcHelper.class.getName());
        }
    }

    public static AbstractOperation preprocessSecurityHook(String sql, String methodName, String className, Map<String, String> params, boolean isPrepared) {
        try {
            if (sql == null || sql.trim().isEmpty()) {
                return null;
            }
            SQLOperation sqlOperation = new SQLOperation(className, methodName);
            sqlOperation.setQuery(sql);
            sqlOperation.setDbName(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, String.class));

            sqlOperation.setPreparedCall(isPrepared);
            sqlOperation.setParams(params);

            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
            NewRelicSecurity.getAgent().registerOperation(sqlOperation);
            return sqlOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, R2DBC_GENERIC, e.getMessage()), e, R2dbcHelper.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, R2DBC_GENERIC, e.getMessage()), e, R2dbcHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, R2DBC_GENERIC, e.getMessage()), e, R2dbcHelper.class.getName());
        }
        return null;
    }

    public static boolean acquireLockIfPossible(VulnerabilityCaseType sqlDbCommand) {
        return GenericHelper.acquireLockIfPossible(sqlDbCommand, getNrSecCustomAttribName());
    }

    public static void releaseLock() {
        GenericHelper.releaseLock(getNrSecCustomAttribName());
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }
}
