/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.mule.module.http.internal.domain.response;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.ExactClass, originalName = "org.mule.module.http.internal.domain.response.HttpResponseBuilder")
public class HttpResponseBuilder_Instrumentation {
    
    private ResponseStatus responseStatus = Weaver.callOriginal();

    public HttpResponse build() {
        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseCode(responseStatus.getStatusCode());
        return Weaver.callOriginal();
    }



}
