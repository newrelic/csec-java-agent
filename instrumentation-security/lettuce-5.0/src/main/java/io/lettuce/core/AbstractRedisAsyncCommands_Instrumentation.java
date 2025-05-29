/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package io.lettuce.core;

import com.newrelic.agent.security.instrumentation.lettuce_6_0.LettuceUtils;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RedisOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.lettuce.core.api.StatefulConnection;
import io.lettuce.core.protocol.AsyncCommand;
import io.lettuce.core.protocol.CommandArgsCsecUtils;
import io.lettuce.core.protocol.CommandArgs_Instrumentation;
import io.lettuce.core.protocol.RedisCommand_Instrumentation;

import java.util.ArrayList;
import java.util.List;

@Weave(originalName = "io.lettuce.core.AbstractRedisAsyncCommands")
public abstract class AbstractRedisAsyncCommands_Instrumentation<K, V> {

    public abstract StatefulConnection<K, V> getConnection();

    @SuppressWarnings("unchecked")
    @Trace
    public <T> AsyncCommand<K, V, T> dispatch(RedisCommand_Instrumentation<K, V, T> cmd) {
        boolean isLockAcquired = acquireLockIfPossible(VulnerabilityCaseType.CACHING_DATA_STORE);
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = preprocessSecurityHook(cmd, LettuceUtils.METHOD_DISPATCH);
        }

        AsyncCommand<K, V, T> returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        registerExitOperation(isLockAcquired, operation);

        return returnVal;
    }

    private void registerExitOperation(boolean isProcessingAllowed, com.newrelic.api.agent.security.schema.AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExistsEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, LettuceUtils.LETTUCE_5_0, e.getMessage()), e, AbstractRedisAsyncCommands_Instrumentation.class.getName());
        }
    }

    private <T> AbstractOperation preprocessSecurityHook(RedisCommand_Instrumentation<K,V,T> cmd, String methodDispatch) {
        try {
            String type = cmd.getType().toString();
            CommandArgs_Instrumentation commandArgs = cmd.getArgs();
            List<Object> arguments = new ArrayList<>();
            for(int i=0 ; i<commandArgs.count(); i++){
                Object arg = CommandArgsCsecUtils.getSingularArgs(commandArgs).get(i);
                arguments.add(CommandArgsCsecUtils.getArgument(arg));
            }
            RedisOperation redisOperation = new RedisOperation(this.getClass().getName(), "dispatch", type, arguments);
            NewRelicSecurity.getAgent().registerOperation(redisOperation);
            return redisOperation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LettuceUtils.LETTUCE_5_0, e.getMessage()), e, AbstractRedisAsyncCommands_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LettuceUtils.LETTUCE_5_0, e.getMessage()), e, AbstractRedisAsyncCommands_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LettuceUtils.LETTUCE_5_0, e.getMessage()), e, AbstractRedisAsyncCommands_Instrumentation.class.getName());
        }
        return null;
    }

    private void releaseLock() {
        GenericHelper.releaseLock(LettuceUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
    }

    private boolean acquireLockIfPossible(VulnerabilityCaseType cachingDataStore) {
        return GenericHelper.acquireLockIfPossible(cachingDataStore, LettuceUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
    }
}
