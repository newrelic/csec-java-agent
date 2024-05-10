/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.springframework.web.reactive.function.client;

import com.newrelic.agent.security.instrumentation.spring.client5.SpringWebClientHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import reactor.core.publisher.Mono;

@Weave(type = MatchType.Interface, originalName = "org.springframework.web.reactive.function.client.ExchangeFunction")
public class ExchangeFunction_Instrumentation {

    public Mono<ClientResponse> exchange(ClientRequest request) {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = SpringWebClientHelper.preprocessSecurityHook(request.url(), request.method(), this.getClass().getName(), SpringWebClientHelper.METHOD_EXECHANGE);
            ClientRequest updatedRequest = SpringWebClientHelper.addSecurityHeaders(request, operation);
            if (updatedRequest != null) {
                request = updatedRequest;
            }
        }
        Mono<ClientResponse> response;
        try {
            response = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        SpringWebClientHelper.registerExitOperation(isLockAcquired, operation);
        return response;
    }

    private void releaseLock() {
        GenericHelper.releaseLock(SpringWebClientHelper.getNrSecCustomAttribName());
    }


    private boolean acquireLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(SpringWebClientHelper.getNrSecCustomAttribName());
    }

}
