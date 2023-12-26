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
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RedisOperation;
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
        boolean isLockAcquired = acquireLockIfPossible();
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
        } catch (Throwable ignored){}
    }

    private <T> AbstractOperation preprocessSecurityHook(RedisCommand_Instrumentation<K,V,T> cmd, String methodDispatch) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()){
                return null;
            }
            String type = cmd.getType().name();
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
                throw e;
            }
        }
        return null;
    }

    private void releaseLock() {
        try {
            GenericHelper.releaseLock(LettuceUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(LettuceUtils.NR_SEC_CUSTOM_ATTRIB_NAME);
        } catch (Throwable ignored) {}
        return false;
    }
}
