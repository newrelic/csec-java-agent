/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.mule.module.http.internal.domain.response;

import com.newrelic.agent.security.instrumentation.mule36.MuleHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.mule.module.http.internal.domain.HttpEntity;

@Weave(type = MatchType.ExactClass, originalName = "org.mule.module.http.internal.domain.response.HttpResponseBuilder")
public class HttpResponseBuilder_Instrumentation {

    private ResponseStatus responseStatus = Weaver.callOriginal();
    private HttpEntity body = Weaver.callOriginal();

    public HttpResponse build() {
        HttpResponse response = Weaver.callOriginal();
        postProcessSecurityHook(response);
        return response;
    }

    private void postProcessSecurityHook(HttpResponse response) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            if (body != null) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(MuleHelper.getNrSecCustomAttribName(MuleHelper.getNrSecCustomAttribName(MuleHelper.RESPONSE_ENTITY_STREAM)), body.hashCode());
            }
            com.newrelic.api.agent.security.schema.HttpResponse securityResponse = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse();

            MuleHelper.processHttpResponseHeaders(securityResponse, response);
            securityResponse.setResponseCode(response.getStatusCode());
            securityResponse.setResponseContentType(MuleHelper.getContentType(securityResponse.getHeaders()));
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_PARSING_HTTP_RESPONSE, MuleHelper.MULE_36, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.ERROR_PARSING_HTTP_RESPONSE, MuleHelper.MULE_36, e.getMessage()), e, this.getClass().getName());
        }
    }
}
